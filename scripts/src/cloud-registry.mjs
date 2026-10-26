import { createHash, randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import { objectIdPattern } from './projects.mjs';
import { fail } from './errors.mjs';

const NS = 'cloud-sso', KEY = 'registry:v1', TTL = 5 * 60000, MAX = 50;
const unsafe = /[<>\u0000-\u0009\u000b-\u001f\u007f-\u009f\u200e\u200f\u202a-\u202e\u2066-\u2069\uD800-\uDFFF]/u;
function shape(value, allowed, required = allowed) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).some(key => !allowed.includes(key)) || required.some(key => !Object.hasOwn(value, key))) {
    fail(400, 'Invalid cloud connection fields; unknown fields and raw secrets are not accepted');
  }
}
function text(value, name, max, empty = false, multiline = false) {
  if (typeof value !== 'string' || value.length > max || (!empty && !value.length) ||
      value !== value.trim() || unsafe.test(value) || (!multiline && value.includes('\n')) ||
      /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----|(?:password|client[_-]?secret)\s*[:=]/i.test(value)) {
    fail(400, `Invalid bounded public ${name}`);
  }
  return value;
}
function https(value, name) {
  text(value, name, 512);
  let url;
  try { url = new URL(value); } catch { fail(400, `Invalid HTTPS ${name}`); }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash ||
      (url.port && url.port !== '443') || isIP(url.hostname.replace(/[[\]]/g, '')) ||
      !url.hostname.includes('.') || /[\\\s]/.test(value)) {
    fail(400, `${name} must be a public HTTPS URL without credentials, query or fragment`);
  }
  return url.href;
}
function samlAudience(value) {
  text(value, 'SAML audience / entity ID', 512);
  let decoded;
  try { decoded = decodeURIComponent(value); } catch { fail(400, 'Invalid encoded SAML audience / entity ID'); }
  text(decoded, 'SAML audience / entity ID', 512);
  if (/[?#\s\\]/u.test(value) || /[?#\s\\]/u.test(decoded)) {
    fail(400, 'SAML audience / entity ID cannot contain whitespace, queries or fragments');
  }
  if (/^https:\/\//i.test(value)) https(value, 'SAML audience / entity ID');
  else if (!/^urn:[a-z0-9][a-z0-9-]{0,30}[a-z0-9]:[a-z0-9._~!$&'()*+,;=:@%/-]+$/i.test(value)) {
    fail(400, 'SAML audience / entity ID must be an absolute HTTPS identifier or bounded URN');
  }
  // Entity IDs are opaque identifiers: validation must not append a slash or change their case.
  return value;
}
export function parseCloudDraft(value) {
  shape(value, ['name', 'cloud', 'protocol', 'configuration', 'notes'], ['name', 'cloud', 'protocol', 'configuration']);
  const name = text(value.name, 'name', 100);
  if (!['azure', 'aws', 'other'].includes(value.cloud) || !['SAML', 'OIDC'].includes(value.protocol)) {
    fail(400, 'Cloud must be azure/aws/other and protocol must be SAML/OIDC');
  }
  let configuration;
  if (value.cloud === 'azure') {
    shape(value.configuration, ['tenantId']);
    if (typeof value.configuration.tenantId !== 'string' || !objectIdPattern.test(value.configuration.tenantId) ||
        value.configuration.tenantId === '00000000-0000-0000-0000-000000000000') fail(400, 'Invalid Azure tenantId');
    configuration = { tenantId: value.configuration.tenantId.toLowerCase() };
  } else {
    const keys = value.protocol === 'SAML' ? ['metadataUrl', 'acsUrl', 'audience'] : ['metadataUrl', 'issuerUrl', 'clientId'];
    shape(value.configuration, keys, []);
    configuration = {};
    for (const key of keys) if (Object.hasOwn(value.configuration, key)) {
      configuration[key] = key === 'clientId' ? text(value.configuration[key], 'public clientId', 160) :
        key === 'audience' ? samlAudience(value.configuration[key]) : https(value.configuration[key], key);
    }
  }
  return { name, cloud: value.cloud, protocol: value.protocol, configuration,
    notes: text(value.notes ?? '', 'notes', 1000, true, true) };
}
const supported = item => item.cloud === 'azure' && item.protocol === 'SAML';
const exactKeys = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const stable = value => value && typeof value === 'object' ?
  (Array.isArray(value) ? value.map(stable) : Object.fromEntries(Object.keys(value).sort().map(key => [key, stable(value[key])]))) : value;
const fingerprint = item => createHash('sha256').update(JSON.stringify(stable(item))).digest('hex');
function revision(value, initial = false) {
  if (!Number.isSafeInteger(value) || value < (initial ? 0 : 1)) fail(400, 'A numeric expectedRevision is required');
}
function id(value) {
  if (typeof value !== 'string' || !objectIdPattern.test(value)) fail(400, 'A valid server-issued connection or plan ID is required');
  return value.toLowerCase();
}

export class CloudRegistry {
  constructor(storage, config, now = Date.now) { this.storage = storage; this.config = config; this.now = now; }
  async document() {
    const doc = await this.storage.get(NS, KEY);
    if (!doc) return { schemaVersion: 1, issuer: this.config.issuer, revision: 0, connections: [], plans: [] };
    if (!exactKeys(doc, ['schemaVersion', 'issuer', 'revision', 'connections', 'plans']) ||
        doc.schemaVersion !== 1 || doc.issuer !== this.config.issuer || !Number.isSafeInteger(doc.revision) || doc.revision < 0 ||
        !Array.isArray(doc.connections) || doc.connections.length > MAX || !Array.isArray(doc.plans) || doc.plans.length > MAX ||
        Buffer.byteLength(JSON.stringify(doc)) > 256 * 1024 ||
        new Set(doc.connections.map(item => item?.id)).size !== doc.connections.length) {
      fail(503, 'Cloud registry schema or trusted issuer differs; operator recovery is required');
    }
    for (const item of doc.connections) {
      if (!exactKeys(item, ['id', 'revision', 'name', 'cloud', 'protocol', 'configuration', 'notes', 'status', 'validation', 'createdAt', 'updatedAt']) ||
          !objectIdPattern.test(item.id) || !Number.isSafeInteger(item.revision) || item.revision < 1 ||
          !Number.isSafeInteger(item.createdAt) || !Number.isSafeInteger(item.updatedAt) ||
          !['DRAFT', 'ENABLED', 'DISABLED'].includes(item.status) || (!supported(item) && item.status !== 'DRAFT') ||
          (item.status === 'ENABLED' && item.validation?.supported !== true)) {
        fail(503, 'Cloud registry record schema or destination state differs; operator recovery is required');
      }
      try {
        parseCloudDraft({ name: item.name, cloud: item.cloud, protocol: item.protocol, configuration: item.configuration, notes: item.notes });
      } catch (error) {
        if (error.status === 400) fail(503, 'Stored cloud configuration is invalid; operator recovery is required');
        throw error;
      }
      const v = item.validation;
      if (v !== null && (!exactKeys(v, ['supported', 'atRevision', 'checkedAt', 'message']) ||
          v.supported !== supported(item) || !Number.isSafeInteger(v.atRevision) || v.atRevision < 1 || v.atRevision > item.revision ||
          !Number.isSafeInteger(v.checkedAt) || typeof v.message !== 'string' || v.message.length > 256 || unsafe.test(v.message))) {
        fail(503, 'Stored validation evidence is invalid; operator recovery is required');
      }
    }
    const destinations = doc.connections.filter(item => supported(item) && item.status === 'ENABLED');
    if (new Set(destinations.map(item => item.configuration.tenantId)).size !== destinations.length ||
        new Set(doc.plans.map(plan => plan?.id)).size !== doc.plans.length ||
        doc.plans.some(plan => !exactKeys(plan, ['id', 'connectionId', 'expectedRevision', 'action', 'actor', 'fingerprint', 'expiresAt']) ||
          !objectIdPattern.test(plan.id) || !doc.connections.some(item => item.id === plan.connectionId) ||
          !Number.isSafeInteger(plan.expectedRevision) || plan.expectedRevision < 1 || !['enable', 'disable'].includes(plan.action) ||
          typeof plan.actor !== 'string' || plan.actor.length > 100 || !/^[a-f0-9]{64}$/.test(plan.fingerprint) ||
          !Number.isSafeInteger(plan.expiresAt))) {
      fail(503, 'Stored destinations or plans are ambiguous or invalid; operator recovery is required');
    }
    return doc;
  }
  public(item) {
    return { ...item, adapterSupported: supported(item), externalSsoVerified: false,
      effective: supported(item) ? {
        keycloakIssuer: this.config.issuer,
        metadataUrl: `${this.config.issuer}/protocol/saml/descriptor`,
        samlSsoUrl: `${this.config.issuer}/protocol/saml`,
        audience: `https://login.microsoftonline.com/${item.configuration.tenantId}/`,
        acsUrl: 'https://login.microsoftonline.com/login.srf'
      } : null };
  }
  find(doc, connectionId, expectedRevision) {
    const item = doc.connections.find(item => item.id === id(connectionId));
    if (!item) fail(404, 'Cloud connection not found');
    if (expectedRevision !== undefined) {
      revision(expectedRevision);
      if (item.revision !== expectedRevision) fail(409, 'Connection revision changed; refresh and review again');
    }
    return item;
  }
  async save(doc, event, actor, item) {
    doc.revision++;
    doc.plans = doc.plans.filter(plan => plan.expiresAt > this.now());
    if (Buffer.byteLength(JSON.stringify(doc)) > 256 * 1024) fail(409, 'Bounded cloud registry is full');
    await this.storage.put(NS, KEY, doc);
    await this.storage.audit(event, actor, { recordId: item.id, revision: item.revision, status: item.status });
  }
  async list() {
    const doc = await this.document();
    return { schemaVersion: 1, revision: doc.revision, connections: doc.connections.map(item => this.public(item)) };
  }
  async create(body, actor) {
    shape(body, ['expectedRevision', 'connection']); revision(body.expectedRevision, true);
    if (body.expectedRevision !== 0) fail(409, 'New connections require expectedRevision=0');
    const draft = parseCloudDraft(body.connection);
    return this.storage.withLock(async () => {
      const doc = await this.document();
      if (doc.connections.length >= MAX) fail(409, 'Cloud registry permits at most 50 connections');
      const item = { id: randomUUID(), revision: 1, ...draft, status: 'DRAFT', validation: null,
        createdAt: this.now(), updatedAt: this.now() };
      doc.connections.push(item);
      await this.save(doc, 'cloud.connection.created', actor, item);
      return { connection: this.public(item), registryRevision: doc.revision };
    });
  }
  async edit(connectionId, body, actor) {
    shape(body, ['expectedRevision', 'connection']);
    const draft = parseCloudDraft(body.connection);
    return this.storage.withLock(async () => {
      const doc = await this.document(), item = this.find(doc, connectionId, body.expectedRevision);
      if (item.status === 'ENABLED') fail(409, 'Disable the destination using a reviewed plan before editing');
      Object.assign(item, draft, { revision: item.revision + 1, status: 'DRAFT', validation: null, updatedAt: this.now() });
      await this.save(doc, 'cloud.connection.edited', actor, item);
      return { connection: this.public(item), registryRevision: doc.revision };
    });
  }
  async validate(connectionId, body, actor) {
    shape(body, ['expectedRevision']);
    return this.storage.withLock(async () => {
      const doc = await this.document(), item = this.find(doc, connectionId, body.expectedRevision);
      if (item.status === 'ENABLED') fail(409, 'Enabled destinations cannot be changed; disable before validation or editing');
      item.revision++; item.updatedAt = this.now();
      item.validation = { supported: supported(item), atRevision: item.revision, checkedAt: this.now(),
        message: supported(item) ? 'Azure SAML adapter configuration is locally valid. External trust and SSO are not verified.' :
          'Adapter unsupported: this cloud/protocol is Draft only. No external URLs were fetched or trust configured.' };
      await this.save(doc, 'cloud.connection.validated', actor, item);
      return { connection: this.public(item), registryRevision: doc.revision };
    });
  }
  assertAction(doc, item, action) {
    if (!supported(item)) fail(409, 'Adapter unsupported; this cloud/protocol must remain Draft');
    if (action === 'enable') {
      if (item.status === 'ENABLED') fail(409, 'Destination is already enabled');
      if (!item.validation?.supported || item.validation.atRevision !== item.revision) {
        fail(409, 'Validate this exact connection revision before previewing enable');
      }
      if (doc.connections.some(other => other.id !== item.id && other.status === 'ENABLED' &&
          supported(other) && other.configuration.tenantId === item.configuration.tenantId)) {
        fail(409, 'An enabled Azure destination already exists for this tenant');
      }
    } else if (action === 'disable') {
      if (item.status !== 'ENABLED') fail(409, 'Only an enabled destination can be disabled');
    } else fail(400, 'Action must be enable or disable');
  }
  async preview(connectionId, body, actor) {
    shape(body, ['expectedRevision', 'action']);
    return this.storage.withLock(async () => {
      const doc = await this.document(), item = this.find(doc, connectionId, body.expectedRevision);
      this.assertAction(doc, item, body.action);
      doc.plans = doc.plans.filter(plan => plan.expiresAt > this.now());
      if (doc.plans.length >= MAX) fail(429, 'Too many active plans; wait for the five-minute expiry');
      const plan = { id: randomUUID(), connectionId: item.id, expectedRevision: item.revision,
        action: body.action, actor, fingerprint: fingerprint(item), expiresAt: this.now() + TTL };
      doc.plans.push(plan);
      await this.save(doc, 'cloud.connection.previewed', actor, item);
      return { plan: { id: plan.id, connectionId: item.id, expectedRevision: item.revision, action: plan.action,
        expiresAt: plan.expiresAt, externalSsoVerified: false,
        effect: plan.action === 'enable' ? 'Enable destination availability only. External SSO is not verified.' :
          'Disable new CMP project launches for this destination. Existing external browser sessions are not revoked.' } };
    });
  }
  async apply(connectionId, body, actor) {
    shape(body, ['expectedRevision', 'planId']); revision(body.expectedRevision); id(body.planId);
    return this.storage.withLock(async () => {
      const doc = await this.document(), item = this.find(doc, connectionId, body.expectedRevision);
      const plan = doc.plans.find(plan => plan.id === body.planId);
      if (!plan || plan.connectionId !== item.id || plan.actor !== actor || plan.expiresAt <= this.now() ||
          plan.expectedRevision !== item.revision || plan.fingerprint !== fingerprint(item)) {
        fail(409, 'Plan is missing, expired, consumed or stale; preview the exact current revision again');
      }
      this.assertAction(doc, item, plan.action);
      item.status = plan.action === 'enable' ? 'ENABLED' : 'DISABLED';
      item.revision++; item.updatedAt = this.now();
      doc.plans = doc.plans.filter(other => other.id !== plan.id);
      await this.save(doc, `cloud.connection.${plan.action === 'enable' ? 'enabled' : 'disabled'}`, actor, item);
      return { status: 'applied', connection: this.public(item), externalSsoVerified: false };
    });
  }
  async setup(connectionId) {
    const item = this.find(await this.document(), connectionId), connection = this.public(item);
    return { schemaVersion: 1, connectionId: item.id, revision: item.revision, cloud: item.cloud, protocol: item.protocol,
      externalSsoVerified: false, adapterSupported: supported(item), configuration: { ...item.configuration }, effective: connection.effective,
      keycloak: { issuer: this.config.issuer, samlMetadataUrl: `${this.config.issuer}/protocol/saml/descriptor`,
        samlSsoUrl: `${this.config.issuer}/protocol/saml`, oidcDiscoveryUrl: `${this.config.issuer}/.well-known/openid-configuration` },
      steps: supported(item) ? [
        'Review the public Keycloak metadata, signing certificate and Azure audience/ACS with the target tenant administrator.',
        'Configure and save external workforce B2B domainless SAML trust separately in Entra. CMP does not write that trust.',
        'Link only real external identities using the actual persistent SAML NameID; do not assume it equals the OIDC subject.',
        'Test real browser sign-in, first-use consent, MFA and Conditional Access. Availability does not prove SSO.',
        'Configure Azure RBAC separately. CMP project ADMINISTRATOR is not a platform administrator or an Azure role grant.'
      ] : ['Adapter unsupported. This draft cannot be activated, launch a portal or configure external trust.'] };
  }
  destinations(doc) { return doc.connections.filter(item => supported(item) && item.status === 'ENABLED'); }
  async projectAvailability(projects) {
    const tenants = new Set(this.destinations(await this.document()).map(item => item.configuration.tenantId));
    return projects.map(project => {
      const available = tenants.has(project.tenantId);
      return { ...project, portalPath: available ? project.portalPath : null, destinationAvailable: available,
        launchStatus: available ? 'Enabled destination · SSO not verified' : 'Configuration pending' };
    });
  }
  async connectionsFor(projects) {
    const tenants = new Set(projects.map(project => project.tenantId));
    return { connections: this.destinations(await this.document()).filter(item => tenants.has(item.configuration.tenantId))
      .map(item => ({ id: item.id, cloud: 'azure', tenantId: item.configuration.tenantId, status: 'ENABLED', externalSsoVerified: false })) };
  }
  async launch(tenantId, launch) {
    return this.storage.withLock(async () => {
      if (!this.destinations(await this.document()).some(item => item.configuration.tenantId === tenantId)) {
        fail(409, 'Configuration pending: no enabled Azure destination for this assigned project');
      }
      return launch();
    });
  }
}

export function registerCloudAdminRoutes(app, registry, requireAdmin) {
  app.get('/api/cloud/connections', requireAdmin, async (req, res) => res.json(await registry.list()));
  app.post('/api/cloud/connections', requireAdmin, async (req, res) => res.status(201).json(await registry.create(req.body, req.session.user.name)));
  app.put('/api/cloud/connections/:id', requireAdmin, async (req, res) => res.json(await registry.edit(req.params.id, req.body, req.session.user.name)));
  for (const action of ['validate', 'preview', 'apply']) {
    app.post(`/api/cloud/connections/:id/${action}`, requireAdmin, async (req, res) =>
      res.json(await registry[action](req.params.id, req.body, req.session.user.name)));
  }
  app.get('/api/cloud/connections/:id/setup', requireAdmin, async (req, res) => res.json(await registry.setup(req.params.id)));
}
