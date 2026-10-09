function fakeDb(init) {
  const root = init || {};
  const parts = p => String(p || '').split('/').filter(Boolean);
  const get = p => parts(p).reduce((o, k) => (o == null ? o : o[k]), root);
  const set = (p, v) => {
    const k = parts(p); if (!k.length) return;
    let o = root; k.slice(0, -1).forEach(x => { if (typeof o[x] !== 'object' || o[x] === null) o[x] = {}; o = o[x]; });
    if (v === null || v === undefined) delete o[k[k.length - 1]]; else o[k[k.length - 1]] = JSON.parse(JSON.stringify(v));
  };
  const ref = p => ({
    get: async () => ({ val: () => { const v = get(p); return v === undefined ? null : JSON.parse(JSON.stringify(v)); } }),
    set: async v => set(p, v),
    remove: async () => set(p, null),
    update: async o => { Object.keys(o).forEach(k => set((p ? p + '/' : '') + k, o[k])); },
    transaction: async fn => { const cur = get(p); const nv = fn(cur === undefined ? null : cur); set(p, nv); return { snapshot: { val: () => nv } }; }
  });
  return { ref, root };
}
module.exports = fakeDb;
