/** Server-owned aliases and presentation metadata, never endpoint authority.
 * Catalog membership is not availability: only DEMO_MODEL_IDS enables joins.
 */
export const LEGACY_MODEL_ID = 'gemma4-e2b';
export const MODEL_CATALOG = Object.freeze([
  Object.freeze({id:'gemma4-e2b',label:'Gemma 4 E2B',description:'Compact model served from the local GPU cluster.'}),
  Object.freeze({id:'qwen35-4b',label:'Qwen3.5 4B',description:'Local 4B model for the same governed portfolio tools.'}),
  Object.freeze({id:'qwen3-14b',label:'Qwen3 14B distributed',description:'14B model distributed across the local GPU cluster.'}),
]);

export class ModelError extends Error {
  constructor(code, status = 400) {
    super(code); this.name = 'ModelError'; this.code = code; this.status = status;
  }
}

export function isModelId(value) {
  return typeof value === 'string' && MODEL_CATALOG.some(model => model.id === value);
}

export function modelMetadata(id) {
  const model = MODEL_CATALOG.find(model => model.id === id);
  if (!model) throw new ModelError('model_not_available');
  return {...model};
}

export function sessionModel(id) {
  const {label} = modelMetadata(id);
  return {id,label};
}

export function modelConfiguration(env) {
  const raw = env.DEMO_MODEL_IDS ?? LEGACY_MODEL_ID;
  if (typeof raw !== 'string' || !raw || raw.length > 128) throw new ModelError('invalid_model_configuration',503);
  const ids = raw.split(',').map(id => id.trim());
  if (!ids.length || ids.length > MODEL_CATALOG.length || new Set(ids).size !== ids.length || ids.some(id => !isModelId(id)))
    throw new ModelError('invalid_model_configuration',503);
  const defaultModel = env.DEMO_DEFAULT_MODEL ?? LEGACY_MODEL_ID;
  if (!isModelId(defaultModel) || !ids.includes(defaultModel)) throw new ModelError('invalid_model_configuration',503);
  return {models:ids.map(modelMetadata),default_model:defaultModel};
}

export function requireEnabledModel(value, env) {
  if (typeof value !== 'string' || !value) throw new ModelError('model_selection_required');
  if (!modelConfiguration(env).models.some(model => model.id === value)) throw new ModelError('model_not_available');
  return value;
}
