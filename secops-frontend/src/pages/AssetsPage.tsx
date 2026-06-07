import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { assetsApi } from '@/lib/api';
import { useAuthStore } from '@/store/authStore';
import { Server, Plus, Pencil, Trash2, Search, Shield, Wifi, Monitor, HardDrive, ChevronLeft, ChevronRight, Tag, X, Check, Download } from 'lucide-react';
import { safeFormat } from '@/lib/date-utils';

const CRITICALITY_CONFIG = {
  high:   { label: "High",   color: "text-red-400",    badge: "bg-red-500/10 text-red-400 border-red-500/20" },
  medium: { label: "Medium", color: "text-amber-400",  badge: "bg-amber-500/10 text-amber-400 border-amber-500/20" },
  low:    { label: "Low",    color: "text-green-400",  badge: "bg-green-500/10 text-green-400 border-green-500/20" },
};

const OS_ICONS: Record<string, React.ReactNode> = {
  windows: <Monitor className="w-4 h-4" />,
  linux:   <Server className="w-4 h-4" />,
  macos:   <Monitor className="w-4 h-4" />,
  network: <Wifi className="w-4 h-4" />,
  other:   <HardDrive className="w-4 h-4" />,
  unknown: <HardDrive className="w-4 h-4" />,
};

const EMPTY_FORM = { hostname: "", ip: "", os: "linux", criticality: "medium", owner: "", department: "", description: "", tags: "" };

export default function AssetsPage() {
  const qc = useQueryClient();
  const { can } = useAuthStore();
  const canManage = can("rules:write");

  const [search, setSearch] = useState("");
  const [criticality, setCriticality] = useState("");
  const [page, setPage] = useState(1);
  const [showModal, setShowModal] = useState(false);
  const [editAsset, setEditAsset] = useState<any | null>(null);
  const [form, setForm] = useState({ ...EMPTY_FORM });
  const [deleteId, setDeleteId] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);

  const showToast = (msg: string) => { setToast(msg); setTimeout(() => setToast(null), 3000); };

  const { data, isLoading } = useQuery({
    queryKey: ["assets", page, search, criticality],
    queryFn: () => assetsApi.list({ page, limit: 20, ...(search ? { search } : {}), ...(criticality ? { criticality } : {}) }).then(r => r.data),
  });

  const createMutation = useMutation({
    mutationFn: (data: any) => assetsApi.create({ ...data, tags: data.tags ? data.tags.split(",").map((t: string) => t.trim()).filter(Boolean) : [] }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["assets"] }); setShowModal(false); showToast("Asset created"); },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: any }) => assetsApi.update(id, { ...data, tags: data.tags ? data.tags.split(",").map((t: string) => t.trim()).filter(Boolean) : [] }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["assets"] }); setShowModal(false); setEditAsset(null); showToast("Asset updated"); },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => assetsApi.delete(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["assets"] }); setDeleteId(null); showToast("Asset deleted"); },
  });

  const openCreate = () => { setForm({ ...EMPTY_FORM }); setEditAsset(null); setShowModal(true); };
  const openEdit = (asset: any) => {
    setForm({
      hostname: asset.hostname, ip: asset.ip ?? "", os: asset.os ?? "linux",
      criticality: asset.criticality ?? "medium", owner: asset.owner ?? "",
      department: asset.department ?? "", description: asset.description ?? "",
      tags: (asset.tags ?? []).join(", "),
    });
    setEditAsset(asset);
    setShowModal(true);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (editAsset) updateMutation.mutate({ id: editAsset.id, data: form });
    else createMutation.mutate(form);
  };

  const assets = data?.assets ?? [];
  const total = data?.total ?? 0;
  const totalPages = Math.ceil(total / 20);

  const exportCsv = () => {
    if (assets.length === 0) return;
    const headers = ['Hostname', 'IP', 'OS', 'Criticality', 'Owner', 'Department', 'Tags', 'Last Seen'];
    const rows = assets.map((a: any) => [
      a.hostname, a.ip ?? '', a.os ?? '', a.criticality ?? '', a.owner ?? '', a.department ?? '',
      (a.tags ?? []).join('; '),
      a.lastSeen ? new Date(a.lastSeen).toISOString() : '',
    ]);
    const csv = [headers, ...rows].map(r => r.map((v: string) => `"${v.replace(/"/g, '""')}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a2 = document.createElement('a'); a2.href = url; a2.download = `assets-${new Date().toISOString().slice(0, 10)}.csv`;
    a2.click(); URL.revokeObjectURL(url);
  };

  return (
    <>
      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-foreground flex items-center gap-2">
              <Server className="w-6 h-6 text-primary" />
              Asset Inventory
            </h1>
            <p className="text-muted-foreground text-sm mt-1">
              {total} assets tracked · Used for enrichment and risk scoring
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={exportCsv} disabled={assets.length === 0} className="flex items-center gap-2 px-4 py-2 bg-secondary border border-border text-foreground rounded-lg hover:bg-secondary/80 text-sm font-medium disabled:opacity-40">
              <Download className="w-4 h-4" /> Export CSV
            </button>
            {canManage && (
              <button onClick={openCreate} className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 text-sm font-medium">
                <Plus className="w-4 h-4" /> Add Asset
              </button>
            )}
          </div>
        </div>

        {/* Filters */}
        <div className="flex gap-3 flex-wrap">
          <div className="flex-1 min-w-48 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <input
              value={search}
              onChange={e => { setSearch(e.target.value); setPage(1); }}
              placeholder="Search hostname, IP, owner..."
              className="w-full pl-9 pr-3 py-2 bg-card border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
            />
          </div>
          <select
            value={criticality}
            onChange={e => { setCriticality(e.target.value); setPage(1); }}
            aria-label="Filter by criticality"
            className="px-3 py-2 bg-card border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
          >
            <option value="">All Criticality</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>

        {/* Table */}
        <div className="bg-card border border-border rounded-lg overflow-hidden">
          {isLoading ? (
            <div className="flex items-center justify-center h-48 text-muted-foreground">
              <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin mr-3" />
              Loading assets...
            </div>
          ) : assets.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-48 text-muted-foreground">
              <Server className="w-10 h-10 mb-3 opacity-20" />
              <p className="font-medium">No assets found</p>
              <p className="text-sm">Add assets to enable enrichment and risk scoring</p>
            </div>
          ) : (
            <table className="w-full">
              <thead>
                <tr className="border-b border-border bg-background/50">
                  <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground uppercase tracking-wider">Hostname</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground uppercase tracking-wider">IP</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground uppercase tracking-wider">OS</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground uppercase tracking-wider">Criticality</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground uppercase tracking-wider">Owner</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground uppercase tracking-wider">Tags</th>
                  <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground uppercase tracking-wider">Last Seen</th>
                  {canManage && <th className="text-right px-4 py-3 text-xs font-medium text-muted-foreground uppercase tracking-wider">Actions</th>}
                </tr>
              </thead>
              <tbody>
                {assets.map((asset: any, i: number) => {
                  const crit = CRITICALITY_CONFIG[asset.criticality as keyof typeof CRITICALITY_CONFIG] ?? CRITICALITY_CONFIG.medium;
                  return (
                    <tr key={asset.id} className={`border-b border-border/50 hover:bg-background/50 ${i % 2 === 0 ? '' : 'bg-background/20'}`}>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <div className={crit.color}>{OS_ICONS[asset.os ?? "unknown"] ?? <HardDrive className="w-4 h-4" />}</div>
                          <span className="font-mono text-sm text-foreground font-medium">{asset.hostname}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3 font-mono text-sm text-muted-foreground">{asset.ip ?? "—"}</td>
                      <td className="px-4 py-3 text-sm text-muted-foreground capitalize">{asset.os ?? "—"}</td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs border ${crit.badge}`}>
                          <Shield className="w-3 h-3" />
                          {crit.label}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-sm text-muted-foreground">
                        <div>{asset.owner ?? "—"}</div>
                        {asset.department && <div className="text-xs opacity-60">{asset.department}</div>}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap gap-1">
                          {(asset.tags ?? []).map((tag: string) => (
                            <span key={tag} className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-xs bg-primary/10 text-primary border border-primary/20">
                              <Tag className="w-2.5 h-2.5" />{tag}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-xs text-muted-foreground">
                        {safeFormat(asset.lastSeen, "MMM d, HH:mm")}
                      </td>
                      {canManage && (
                        <td className="px-4 py-3 text-right">
                          <div className="flex items-center justify-end gap-1">
                            <button onClick={() => openEdit(asset)} aria-label="Edit asset" className="p-1.5 text-muted-foreground hover:text-primary hover:bg-primary/10 rounded">
                              <Pencil className="w-3.5 h-3.5" />
                            </button>
                            <button onClick={() => setDeleteId(asset.id)} aria-label="Delete asset" className="p-1.5 text-muted-foreground hover:text-red-400 hover:bg-red-500/10 rounded">
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </td>
                      )}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between">
            <span className="text-sm text-muted-foreground">
              Showing {(page - 1) * 20 + 1}–{Math.min(page * 20, total)} of {total}
            </span>
            <div className="flex gap-2">
              <button disabled={page === 1} onClick={() => setPage(p => p - 1)}
                aria-label="Previous page"
                className="p-1.5 rounded border border-border disabled:opacity-40 hover:bg-card">
                <ChevronLeft className="w-4 h-4" />
              </button>
              <button disabled={page >= totalPages} onClick={() => setPage(p => p + 1)}
                aria-label="Next page"
                className="p-1.5 rounded border border-border disabled:opacity-40 hover:bg-card">
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}

        {/* Add/Edit Modal */}
        {showModal && (
          <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
            <div className="bg-card border border-border rounded-xl w-full max-w-lg shadow-2xl">
              <div className="flex items-center justify-between px-6 py-4 border-b border-border">
                <h2 className="font-semibold text-foreground">{editAsset ? "Edit Asset" : "Add Asset"}</h2>
                <button onClick={() => { setShowModal(false); setEditAsset(null); }} aria-label="Close" className="text-muted-foreground hover:text-foreground">
                  <X className="w-5 h-5" />
                </button>
              </div>
              <form onSubmit={handleSubmit} className="p-6 space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div className="col-span-2">
                    <label className="block text-xs text-muted-foreground mb-1">Hostname *</label>
                    <input required value={form.hostname} onChange={e => setForm(f => ({ ...f, hostname: e.target.value }))}
                      placeholder="DC01.corp.local"
                      className="w-full px-3 py-2 bg-background border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary font-mono" />
                  </div>
                  <div>
                    <label className="block text-xs text-muted-foreground mb-1">IP Address</label>
                    <input value={form.ip} onChange={e => setForm(f => ({ ...f, ip: e.target.value }))}
                      placeholder="10.0.0.1"
                      className="w-full px-3 py-2 bg-background border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary font-mono" />
                  </div>
                  <div>
                    <label className="block text-xs text-muted-foreground mb-1">OS</label>
                    <select value={form.os} onChange={e => setForm(f => ({ ...f, os: e.target.value }))}
                      aria-label="Operating system"
                      className="w-full px-3 py-2 bg-background border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary">
                      <option value="windows">Windows</option>
                      <option value="linux">Linux</option>
                      <option value="macos">macOS</option>
                      <option value="network">Network</option>
                      <option value="other">Other</option>
                      <option value="unknown">Unknown</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-xs text-muted-foreground mb-1">Criticality</label>
                    <select value={form.criticality} onChange={e => setForm(f => ({ ...f, criticality: e.target.value }))}
                      aria-label="Criticality"
                      className="w-full px-3 py-2 bg-background border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary">
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-xs text-muted-foreground mb-1">Owner</label>
                    <input value={form.owner} onChange={e => setForm(f => ({ ...f, owner: e.target.value }))}
                      placeholder="Infrastructure Team"
                      className="w-full px-3 py-2 bg-background border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary" />
                  </div>
                  <div>
                    <label className="block text-xs text-muted-foreground mb-1">Department</label>
                    <input value={form.department} onChange={e => setForm(f => ({ ...f, department: e.target.value }))}
                      placeholder="IT"
                      className="w-full px-3 py-2 bg-background border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary" />
                  </div>
                  <div className="col-span-2">
                    <label className="block text-xs text-muted-foreground mb-1">Tags (comma-separated)</label>
                    <input value={form.tags} onChange={e => setForm(f => ({ ...f, tags: e.target.value }))}
                      placeholder="domain-controller, prod, sensitive"
                      className="w-full px-3 py-2 bg-background border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary" />
                  </div>
                  <div className="col-span-2">
                    <label className="block text-xs text-muted-foreground mb-1">Description</label>
                    <textarea value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
                      placeholder="Optional description..."
                      rows={2}
                      className="w-full px-3 py-2 bg-background border border-border rounded-lg text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-primary resize-none" />
                  </div>
                </div>
                <div className="flex justify-end gap-3 pt-2">
                  <button type="button" onClick={() => { setShowModal(false); setEditAsset(null); }}
                    className="px-4 py-2 text-sm text-muted-foreground hover:text-foreground border border-border rounded-lg hover:bg-background">
                    Cancel
                  </button>
                  <button type="submit" disabled={createMutation.isPending || updateMutation.isPending}
                    className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 text-sm font-medium disabled:opacity-50">
                    <Check className="w-4 h-4" />
                    {editAsset ? "Save Changes" : "Create Asset"}
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}

        {/* Delete Confirm */}
        {deleteId && (
          <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
            <div className="bg-card border border-border rounded-xl w-full max-w-sm shadow-2xl p-6 space-y-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-full bg-red-500/10 flex items-center justify-center">
                  <Trash2 className="w-5 h-5 text-red-400" />
                </div>
                <div>
                  <h3 className="font-semibold text-foreground">Delete Asset</h3>
                  <p className="text-sm text-muted-foreground">This action cannot be undone.</p>
                </div>
              </div>
              <div className="flex justify-end gap-3">
                <button onClick={() => setDeleteId(null)} className="px-4 py-2 text-sm text-muted-foreground border border-border rounded-lg hover:bg-background">
                  Cancel
                </button>
                <button onClick={() => deleteMutation.mutate(deleteId!)} disabled={deleteMutation.isPending}
                  className="px-4 py-2 bg-red-500 text-white rounded-lg hover:bg-red-600 text-sm font-medium disabled:opacity-50">
                  Delete
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Toast */}
        {toast && (
          <div className="fixed bottom-4 right-4 bg-card border border-border rounded-lg px-4 py-3 text-sm text-foreground shadow-lg flex items-center gap-2 z-50">
            <Check className="w-4 h-4 text-green-400" />
            {toast}
          </div>
        )}
      </div>
    </>
  );
}
