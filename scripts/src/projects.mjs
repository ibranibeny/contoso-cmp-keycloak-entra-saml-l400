export const objectIdPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const roles = new Set(['ADMINISTRATOR', 'VIEW', 'BDE_VIEW']);
const invalidCatalog = reason => { throw new Error(`CMP_PROJECTS_JSON: ${reason}`); };

function record(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== fields.length || fields.some(field => !Object.hasOwn(value, field))) {
    invalidCatalog('Each project and membership must contain exactly the documented fields');
  }
}
function safeText(value, max) {
  if (typeof value !== 'string' || !value || value.length > max || value.trim() !== value ||
      /[<>\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/u.test(value)) {
    invalidCatalog(`Strings must be nonempty, safe text of at most ${max} characters with no surrounding whitespace`);
  }
  return value;
}
function identifier(value) {
  if (typeof value !== 'string' || !objectIdPattern.test(value)) invalidCatalog('Subscription, tenant and Entra object IDs must be GUIDs');
  return value.toLowerCase();
}

export function parseProjectCatalog(raw = '[]') {
  if (typeof raw !== 'string' || Buffer.byteLength(raw, 'utf8') > 256 * 1024) invalidCatalog('Catalog must be JSON of at most 256 KiB');
  let value;
  try { value = JSON.parse(raw); }
  catch { invalidCatalog('Catalog must be valid JSON'); }
  if (!Array.isArray(value) || value.length > 100) invalidCatalog('Catalog must be an array of at most 100 projects');
  const ids = new Set();
  return Object.freeze(value.map(project => {
    record(project, ['id', 'name', 'organization', 'tenantId', 'memberships']);
    const id = identifier(project.id);
    if (ids.has(id)) invalidCatalog('Duplicate subscription ID');
    ids.add(id);
    if (!Array.isArray(project.memberships) || project.memberships.length > 100) invalidCatalog('Each project must have an array of at most 100 memberships');
    const subjects = new Set(), objectIds = new Set();
    const memberships = Object.freeze(project.memberships.map(member => {
      record(member, ['subject', 'role', 'entraObjectId']);
      const subject = safeText(member.subject, 255);
      const entraObjectId = identifier(member.entraObjectId);
      if (!roles.has(member.role)) invalidCatalog('Role must be ADMINISTRATOR, VIEW or BDE_VIEW');
      if (subjects.has(subject) || objectIds.has(entraObjectId)) invalidCatalog('Duplicate subject or Entra object ID within a project');
      subjects.add(subject); objectIds.add(entraObjectId);
      return Object.freeze({ subject, role: member.role, entraObjectId });
    }));
    return Object.freeze({
      id, name: safeText(project.name, 160), organization: safeText(project.organization, 160),
      tenantId: identifier(project.tenantId), memberships
    });
  }));
}

export function assignedProjects(config, identity) {
  if (typeof config.issuer !== 'string' || identity?.issuer !== config.issuer || typeof identity?.sub !== 'string') return [];
  return (config.projects || []).flatMap(project => {
    const membership = project.memberships.find(member => member.subject === identity.sub);
    return membership ? [{
      id: project.id, name: project.name, organization: project.organization, tenantId: project.tenantId,
      role: membership.role, portalPath: `/portal/${project.id}`
    }] : [];
  });
}

export function projectPortalUrl(project) {
  if (!project || typeof project.id !== 'string' || !objectIdPattern.test(project.id) ||
      typeof project.tenantId !== 'string' || !objectIdPattern.test(project.tenantId)) {
    throw new Error('Invalid project subscription or tenant identifier');
  }
  return `https://portal.azure.com/#@${project.tenantId.toLowerCase()}/resource/subscriptions/${project.id.toLowerCase()}/overview`;
}
