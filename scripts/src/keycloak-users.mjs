import { createHash } from 'node:crypto';
import { AppError, fail } from './errors.mjs';
import { objectIdPattern } from './projects.mjs';

export const USER_OWNER = 'cmp-user-admin-v1';
export class UserServiceError extends AppError {
  constructor(message, outcome = 'UNKNOWN', upstreamStatus) {
    super(502, message); this.outcome = outcome; this.upstreamStatus = upstreamStatus;
  }
}
const serviceError = (message, outcome, upstreamStatus) => { throw new UserServiceError(message, outcome, upstreamStatus); };
const safe = (value, max) => typeof value === 'string' && value.length <= max &&
  !/[<>\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/u.test(value);

export class KeycloakUsers {
  constructor(config, transport = globalThis.fetch) {
    this.config = config;
    this.transport = transport;
    const publicUrl = new URL(config.keycloakUrl), privateUrl = new URL(config.userAdminUrl);
    if (!config.userAdmin || config.userAdminClientId !== 'cmp-user-admin' || config.realm !== 'cmp-pdf' || config.issuer !== `${publicUrl.origin}/realms/cmp-pdf` ||
        privateUrl.origin !== config.userAdminUrl || privateUrl.protocol !== 'https:' || privateUrl.port !== '8443' ||
        privateUrl.hostname !== publicUrl.hostname || privateUrl.username || privateUrl.password || publicUrl.port) {
      throw new Error('Invalid scoped Keycloak user-administration configuration');
    }
    this.base = `${privateUrl.origin}/admin/realms/cmp-pdf/users`;
  }
  async exchange(url, options, expected, json = true) {
    let response;
    try {
      response = await this.transport(url, { ...options, redirect: 'manual', signal: AbortSignal.timeout(10000) });
    } catch { serviceError('Keycloak user service transport failed or timed out; no automatic retry'); }
    if (!expected.includes(response.status)) {
      await response.body?.cancel();
      const rejected = response.status >= 400 && response.status < 500 && response.status !== 408;
      serviceError(`Keycloak user service refused the request (HTTP ${response.status}); inspect private endpoint and service permissions`,
        rejected ? 'REJECTED' : 'UNKNOWN', response.status);
    }
    if (!json) { await response.body?.cancel(); return; }
    const chunks = []; let length = 0;
    try {
      if (Number(response.headers.get('content-length')) > 256 * 1024) throw new Error('bound');
      if (response.body) {
        for await (const chunk of response.body) {
          length += chunk.byteLength;
          if (length > 256 * 1024) throw new Error('bound');
          chunks.push(chunk);
        }
      }
      return JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch {
      if (response.body && !response.body.locked) await response.body.cancel();
      serviceError('Keycloak user service returned invalid or oversized JSON');
    }
  }
  async token() {
    if (this.cached?.expires > Date.now() + 30000) return this.cached.value;
    const data = await this.exchange(`${this.config.userAdminUrl}/realms/cmp-pdf/protocol/openid-connect/token`, {
      method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'client_credentials', client_id: this.config.userAdminClientId,
        client_secret: this.config.userAdminClientSecret }).toString()
    }, [200]);
    let claims;
    try {
      if (typeof data?.access_token !== 'string' || data.access_token.length > 16000 || data.access_token.split('.').length !== 3) throw new Error();
      claims = JSON.parse(Buffer.from(data.access_token.split('.')[1], 'base64url').toString('utf8'));
    } catch { serviceError('Keycloak returned an invalid user-service token'); }
    const roles = claims?.resource_access?.['realm-management']?.roles;
    if (claims?.iss !== this.config.issuer || claims.azp !== this.config.userAdminClientId ||
        !Number.isInteger(claims.exp) || claims.exp * 1000 <= Date.now() ||
        !Number.isInteger(data.expires_in) || data.expires_in < 1 || data.expires_in > 3600 ||
        !Array.isArray(roles) || !['query-users', 'view-users', 'manage-users'].every(role => roles.includes(role)) ||
        new Set(roles).size !== roles.length ||
        roles.some(role => !['query-users', 'view-users', 'manage-users', 'query-groups'].includes(role)) ||
        Object.entries(claims.resource_access).some(([client, access]) =>
          client !== 'realm-management' && Array.isArray(access?.roles) && access.roles.length)) {
      serviceError('Keycloak user-service token issuer, client, expiry or least-privilege roles mismatch');
    }
    this.cached = { value: data.access_token, expires: Math.min(claims.exp * 1000, Date.now() + data.expires_in * 1000) };
    return this.cached.value;
  }
  async request(method, suffix = '', body, query) {
    const [subject, action, extra] = suffix.slice(1).split('/');
    const allowed = !suffix ? ['GET', 'POST'].includes(method) :
      suffix.startsWith('/') && objectIdPattern.test(subject) && extra === undefined &&
        (action === undefined ? ['GET', 'PUT'].includes(method) :
          action === 'credentials' ? method === 'GET' :
          action === 'logout' ? method === 'POST' :
          ['reset-password', 'execute-actions-email'].includes(action) && method === 'PUT');
    if (!allowed || (query && (suffix || method !== 'GET'))) fail(400, 'Invalid scoped Keycloak user request');
    const url = new URL(`${this.base}${suffix}`);
    if (query) url.search = new URLSearchParams(query).toString();
    const expected = method === 'GET' ? [200] : method === 'POST' && !suffix ? [201] : [204];
    return this.exchange(url.href, { method,
      headers: { authorization: `Bearer ${await this.token()}`, 'content-type': 'application/json' },
      ...(body === undefined ? {} : { body: JSON.stringify(body) })
    }, expected, method === 'GET');
  }
  async search(query, first = 0, max = 2) {
    const users = await this.request('GET', '', undefined, { ...query, first: String(first), max: String(max), briefRepresentation: 'false' });
    if (!Array.isArray(users) || users.length > max) serviceError('Keycloak user service returned invalid bounded pagination');
    return users;
  }
  owned(user) {
    return user?.attributes?.cmpUserManaged?.length === 1 && user.attributes.cmpUserManaged[0] === USER_OWNER &&
      user.attributes.cmpUserOperationId?.length === 1 && objectIdPattern.test(user.attributes.cmpUserOperationId[0]) &&
      !user.serviceAccountClientId && !user.federationLink && !user.federatedIdentities?.length;
  }
  normalize(user) {
    if (!this.owned(user)) fail(404, 'Owned CMP user not found; existing users are never adopted');
    if (typeof user.id !== 'string' || !objectIdPattern.test(user.id) || typeof user.enabled !== 'boolean' ||
        typeof user.emailVerified !== 'boolean' || !safe(user.username, 128) || !user.username ||
        !['email', 'firstName', 'lastName'].every(key => user[key] == null || safe(user[key], key === 'email' ? 254 : 100)) ||
        !Array.isArray(user.requiredActions) || user.requiredActions.length > 20 ||
        user.requiredActions.some(action => !/^[A-Z0-9_]{1,80}$/.test(action))) {
      serviceError('Keycloak user service returned an invalid owned profile');
    }
    return { subject: user.id, username: user.username, email: user.email || '', firstName: user.firstName || '',
      lastName: user.lastName || '', enabled: user.enabled, emailVerified: user.emailVerified,
      requiredActions: [...user.requiredActions].sort(), operationId: user.attributes.cmpUserOperationId[0] };
  }
  async get(subject) {
    if (typeof subject !== 'string' || !objectIdPattern.test(subject)) fail(400, 'A valid immutable Keycloak subject is required');
    let user;
    try { user = await this.request('GET', `/${subject}`); }
    catch (error) {
      if (error instanceof UserServiceError && error.upstreamStatus === 404) fail(404, 'Owned CMP user not found');
      throw error;
    }
    if (user?.id !== subject) serviceError('Keycloak immutable user subject mismatch');
    return this.normalize(user);
  }
  async list(first, max) {
    const raw = await this.search({ q: `cmpUserManaged:${USER_OWNER}` }, first, max);
    return { users: raw.filter(user => this.owned(user)).map(user => this.normalize(user)), nextFirst: raw.length === max ? first + max : null };
  }
  async absent(profile) {
    if ((await this.search({ username: profile.username, exact: 'true' })).length ||
        (profile.email && (await this.search({ email: profile.email, exact: 'true' })).length)) {
      fail(409, 'Username or email already exists; existing accounts are never adopted or reset');
    }
  }
  async create(profile, password, operationId) {
    await this.request('POST', '', {
      ...profile, enabled: true, emailVerified: false,
      attributes: { cmpUserManaged: [USER_OWNER], cmpUserOperationId: [operationId] },
      requiredActions: ['UPDATE_PASSWORD', ...(profile.email ? ['VERIFY_EMAIL'] : [])],
      credentials: [{ type: 'password', temporary: true, value: password }]
    });
    const found = await this.search({ username: profile.username, exact: 'true' });
    if (found.length !== 1 || found[0]?.attributes?.cmpUserOperationId?.[0] !== operationId) {
      serviceError('Created user subject and operation ownership could not be confirmed');
    }
    return this.get(this.normalize(found[0]).subject);
  }
  async enabled(subject, enabled) { await this.request('PUT', `/${subject}`, { enabled }); }
  async reset(subject, password) { await this.request('PUT', `/${subject}/reset-password`, { type: 'password', temporary: true, value: password }); }
  async logout(subject) { await this.request('POST', `/${subject}/logout`); }
  async verifyEmail(subject) { await this.request('PUT', `/${subject}/execute-actions-email`, ['VERIFY_EMAIL']); }
  async credentialRevision(subject) {
    const entries = await this.request('GET', `/${subject}/credentials`);
    if (!Array.isArray(entries) || entries.length > 50 || entries.some(entry =>
      !entry || !objectIdPattern.test(entry.id) || typeof entry.type !== 'string' || !/^[a-z0-9-]{1,64}$/.test(entry.type) ||
      (entry.createdDate !== undefined && (!Number.isSafeInteger(entry.createdDate) || entry.createdDate < 0)))) {
      serviceError('Keycloak returned an invalid bounded credential inventory');
    }
    // Bind only non-secret metadata. Never hash or persist credentialData/secretData/password values.
    const metadata = entries.map(({ id, type, createdDate }) => [id, type, createdDate ?? null]).sort((a, b) => a[0].localeCompare(b[0]));
    return createHash('sha256').update(JSON.stringify(metadata)).digest('hex');
  }
}
