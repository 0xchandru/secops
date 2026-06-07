import React, { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { meApi, ingestApi } from '@/lib/api';
import type { UserSettings } from '@/lib/api';
import { useAuthStore } from '@/store/authStore';
import {
  Settings, User, Bell, Shield, Key, CheckCircle2, Eye, EyeOff, Plus, Copy,
  CheckCheck, Trash2, Loader2, Database, Monitor, Globe, Activity, Server,
  Wifi, WifiOff, Clock, HardDrive, RefreshCw, AlertTriangle, Info, BarChart3,
  Zap, FileText, Download, UploadCloud, Smartphone, Laptop,
} from 'lucide-react';

type Tab = 'profile' | 'notifications' | 'security' | 'apikeys' | 'datasources' | 'system';
const TAB_SECTIONS: { section: string; tabs: { id: Tab; label: string; icon: React.ElementType }[] }[] = [
  {
    section: 'Account',
    tabs: [
      { id: 'profile', label: 'Profile', icon: User },
      { id: 'notifications', label: 'Notifications', icon: Bell },
      { id: 'security', label: 'Security', icon: Shield },
      { id: 'apikeys', label: 'API Keys', icon: Key },
    ],
  },
  {
    section: 'System',
    tabs: [
      { id: 'datasources', label: 'Data Sources', icon: Database },
      { id: 'system', label: 'System Info', icon: Monitor },
    ],
  },
];

function Toast({ msg }: { msg: string }) {
  return (
    <div className="fixed top-6 right-6 z-50 bg-card border border-primary/30 text-foreground px-4 py-3 rounded-xl shadow-2xl text-sm font-medium flex items-center gap-2 animate-in slide-in-from-top-4 duration-200">
      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" /> {msg}
    </div>
  );
}

function ProfileTab({ onSave }: { onSave: (msg: string) => void }) {
  const qc = useQueryClient();
  const user = useAuthStore(s => s.user);

  const { data, isLoading } = useQuery({
    queryKey: ['me-profile'],
    queryFn: () => meApi.getProfile().then(r => r.data.profile),
  });

  const { data: settingsData } = useQuery({
    queryKey: ['me-settings'],
    queryFn: () => meApi.getSettings().then(r => r.data.settings),
  });

  const [displayName, setDisplayName] = useState('');
  const [jobTitle, setJobTitle] = useState('');
  const [timezone, setTimezone] = useState('UTC');

  useEffect(() => {
    if (data) {
      setDisplayName(data.displayName ?? '');
      setJobTitle(data.jobTitle ?? '');
    }
  }, [data]);

  useEffect(() => {
    if (settingsData?.timezone) setTimezone(settingsData.timezone);
  }, [settingsData]);

  const mutation = useMutation({
    mutationFn: () => Promise.all([
      meApi.updateProfile({ displayName, jobTitle }),
      meApi.updateSettings({ timezone }),
    ]),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['me-profile'] });
      qc.invalidateQueries({ queryKey: ['me-settings'] });
      onSave('Profile settings saved');
    },
    onError: () => onSave('Failed to save profile'),
  });

  const initials = (displayName || user?.username || 'U').slice(0, 2).toUpperCase();

  if (isLoading) {
    return <div className="flex items-center justify-center py-16"><Loader2 className="w-6 h-6 animate-spin text-primary" /></div>;
  }

  return (
    <div>
      <h2 className="text-xl font-bold text-foreground mb-6">Profile Settings</h2>
      <div className="flex items-center gap-6 mb-8">
        <div className="w-20 h-20 rounded-full bg-primary/20 border-2 border-primary/50 flex items-center justify-center text-2xl font-bold text-primary shadow-[0_0_15px_rgba(59,130,246,0.3)]">
          {initials}
        </div>
        <div>
          <p className="text-sm text-muted-foreground">Avatar is generated from your name initials</p>
          <p className="text-xs text-muted-foreground mt-1">{data?.email}</p>
        </div>
      </div>
      <div className="space-y-5">
        <div>
          <label className="block text-sm font-medium text-muted-foreground mb-1.5">Display Name</label>
          <input
            type="text"
            value={displayName}
            onChange={e => setDisplayName(e.target.value)}
            className="w-full bg-input border border-border rounded-lg px-4 py-2 text-foreground focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary"
            placeholder="Your display name"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-muted-foreground mb-1.5">Email Address</label>
          <input
            type="email"
            defaultValue={data?.email ?? ''}
            disabled
            aria-label="Email address"
            className="w-full bg-secondary/50 border border-border/50 rounded-lg px-4 py-2 text-muted-foreground cursor-not-allowed"
          />
          <p className="text-xs text-muted-foreground mt-1">Contact your admin to change your email.</p>
        </div>
        <div>
          <label className="block text-sm font-medium text-muted-foreground mb-1.5">Role / Title</label>
          <input
            type="text"
            value={jobTitle}
            onChange={e => setJobTitle(e.target.value)}
            className="w-full bg-input border border-border rounded-lg px-4 py-2 text-foreground focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary"
            placeholder="e.g. Senior Threat Hunter"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-muted-foreground mb-1.5">System Role</label>
          <input
            type="text"
            value={data?.role ?? ''}
            disabled
            aria-label="System role"
            className="w-full bg-secondary/50 border border-border/50 rounded-lg px-4 py-2 text-muted-foreground cursor-not-allowed capitalize"
          />
          <p className="text-xs text-muted-foreground mt-1">Roles are managed by your administrator.</p>
        </div>
        <div>
          <label className="block text-sm font-medium text-muted-foreground mb-1.5">
            <Globe className="w-3.5 h-3.5 inline mr-1.5 relative -top-px" />Timezone
          </label>
          <select
            aria-label="Timezone"
            value={timezone}
            onChange={e => setTimezone(e.target.value)}
            className="w-full bg-input border border-border rounded-lg px-4 py-2 text-foreground focus:outline-none focus:border-primary appearance-none"
          >
            {['UTC', 'America/New_York', 'America/Chicago', 'America/Denver', 'America/Los_Angeles',
              'Europe/London', 'Europe/Berlin', 'Europe/Paris', 'Asia/Tokyo', 'Asia/Shanghai',
              'Asia/Kolkata', 'Australia/Sydney', 'Pacific/Auckland'].map(tz => (
              <option key={tz} value={tz}>{tz.replace(/_/g, ' ')}</option>
            ))}
          </select>
          <p className="text-xs text-muted-foreground mt-1">All timestamps and reports will use this timezone.</p>
        </div>
        {data?.lastLoginAt && (
          <div className="bg-secondary/30 border border-border rounded-lg p-3">
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Clock className="w-3.5 h-3.5" />
              Last login: {new Date(data.lastLoginAt).toLocaleString()}
            </div>
            <div className="flex items-center gap-2 text-xs text-muted-foreground mt-1">
              <Info className="w-3.5 h-3.5" />
              Account created: {new Date(data.createdAt).toLocaleString()}
            </div>
          </div>
        )}
        <div className="pt-4 border-t border-border flex justify-end">
          <button
            onClick={() => mutation.mutate()}
            disabled={mutation.isPending}
            className="px-6 py-2.5 bg-primary text-primary-foreground font-semibold rounded-lg hover:bg-primary/90 transition-all shadow-lg shadow-primary/20 disabled:opacity-50 flex items-center gap-2"
          >
            {mutation.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
            Save Changes
          </button>
        </div>
      </div>
    </div>
  );
}

function NotificationsTab({ onSave }: { onSave: (msg: string) => void }) {
  const qc = useQueryClient();

  const { data: settingsData, isLoading } = useQuery({
    queryKey: ['me-settings'],
    queryFn: () => meApi.getSettings().then(r => r.data.settings),
  });

  const [notifs, setNotifs] = useState<UserSettings['notifications']>({
    emailAlerts: true, emailDigest: false, slackIntegration: false,
    criticalOnly: false, newAlerts: true, assignedAlerts: true,
    ruleMatches: false, weeklyReport: true,
  });

  useEffect(() => {
    if (settingsData?.notifications) setNotifs(settingsData.notifications);
  }, [settingsData]);

  const mutation = useMutation({
    mutationFn: () => meApi.updateSettings({ notifications: notifs }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['me-settings'] });
      onSave('Notification preferences saved');
    },
  });

  const toggle = (k: keyof UserSettings['notifications']) => () => setNotifs(n => ({ ...n, [k]: !n[k] }));
  const Toggle = ({ id }: { id: keyof UserSettings['notifications'] }) => (
    <button aria-label={`Toggle ${id}`} onClick={toggle(id)} className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${notifs[id] ? 'bg-primary' : 'bg-secondary border border-border'}`}>
      <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition-transform ${notifs[id] ? 'translate-x-4' : 'translate-x-0.5'}`} />
    </button>
  );

  if (isLoading) {
    return <div className="flex items-center justify-center py-16"><Loader2 className="w-6 h-6 animate-spin text-primary" /></div>;
  }

  return (
    <div>
      <h2 className="text-xl font-bold text-foreground mb-6">Notification Preferences</h2>

      {/* Alert Channels */}
      <div className="mb-6">
        <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3 flex items-center gap-2">
          <Zap className="w-3.5 h-3.5" /> Delivery Channels
        </h3>
        <div className="space-y-1 bg-secondary/20 border border-border rounded-xl p-4">
          {[
            { label: 'Email Alerts', desc: 'Receive alert notifications via email', id: 'emailAlerts' as const },
            { label: 'Daily Digest', desc: 'Get a summary of daily SOC activity', id: 'emailDigest' as const },
            { label: 'Slack Integration', desc: 'Push alerts to your Slack workspace', id: 'slackIntegration' as const },
          ].map(item => (
            <div key={item.id} className="flex items-center justify-between py-3 border-b border-border/30 last:border-0">
              <div>
                <div className="text-sm font-medium text-foreground">{item.label}</div>
                <div className="text-xs text-muted-foreground mt-0.5">{item.desc}</div>
              </div>
              <Toggle id={item.id} />
            </div>
          ))}
        </div>
      </div>

      {/* Alert Triggers */}
      <div className="mb-6">
        <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3 flex items-center gap-2">
          <Bell className="w-3.5 h-3.5" /> Alert Triggers
        </h3>
        <div className="space-y-1 bg-secondary/20 border border-border rounded-xl p-4">
          {[
            { label: 'Critical Alerts Only', desc: 'Only receive notifications for critical severity', id: 'criticalOnly' as const },
            { label: 'New Alert Assignments', desc: 'Notify when an alert is assigned to you', id: 'assignedAlerts' as const },
            { label: 'Rule Match Notifications', desc: 'Alert when detection rules fire', id: 'ruleMatches' as const },
          ].map(item => (
            <div key={item.id} className="flex items-center justify-between py-3 border-b border-border/30 last:border-0">
              <div>
                <div className="text-sm font-medium text-foreground">{item.label}</div>
                <div className="text-xs text-muted-foreground mt-0.5">{item.desc}</div>
              </div>
              <Toggle id={item.id} />
            </div>
          ))}
        </div>
      </div>

      {/* Reports */}
      <div className="mb-6">
        <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3 flex items-center gap-2">
          <FileText className="w-3.5 h-3.5" /> Reports
        </h3>
        <div className="bg-secondary/20 border border-border rounded-xl p-4">
          <div className="flex items-center justify-between py-2">
            <div>
              <div className="text-sm font-medium text-foreground">Weekly Report</div>
              <div className="text-xs text-muted-foreground mt-0.5">Weekly SOC performance and coverage report</div>
            </div>
            <Toggle id="weeklyReport" />
          </div>
        </div>
      </div>
      <div className="pt-4 mt-2 flex justify-end">
        <button
          onClick={() => mutation.mutate()}
          disabled={mutation.isPending}
          className="px-6 py-2.5 bg-primary text-primary-foreground font-semibold rounded-lg hover:bg-primary/90 transition-all shadow-lg shadow-primary/20 disabled:opacity-50 flex items-center gap-2"
        >
          {mutation.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
          Save Preferences
        </button>
      </div>
    </div>
  );
}

function SecurityTab({ onSave }: { onSave: (msg: string) => void }) {
  const qc = useQueryClient();
  const [currentPw, setCurrentPw] = useState('');
  const [newPw, setNewPw] = useState('');
  const [confirmPw, setConfirmPw] = useState('');
  const [showPw, setShowPw] = useState(false);
  const [pwError, setPwError] = useState('');

  // Password strength helper
  const pwStrength = (() => {
    if (!newPw) return { score: 0, label: '', color: '' };
    let s = 0;
    if (newPw.length >= 8) s++;
    if (newPw.length >= 12) s++;
    if (/[A-Z]/.test(newPw) && /[a-z]/.test(newPw)) s++;
    if (/\d/.test(newPw)) s++;
    if (/[^A-Za-z0-9]/.test(newPw)) s++;
    if (s <= 1) return { score: 1, label: 'Weak', color: 'bg-red-500' };
    if (s <= 2) return { score: 2, label: 'Fair', color: 'bg-amber-500' };
    if (s <= 3) return { score: 3, label: 'Good', color: 'bg-yellow-400' };
    if (s <= 4) return { score: 4, label: 'Strong', color: 'bg-green-400' };
    return { score: 5, label: 'Very Strong', color: 'bg-emerald-500' };
  })();

  const { data: settingsData, isLoading } = useQuery({
    queryKey: ['me-settings'],
    queryFn: () => meApi.getSettings().then(r => r.data.settings),
  });

  const [mfaEnabled, setMfaEnabled] = useState(false);
  const [sessionTimeout, setSessionTimeout] = useState('8');

  useEffect(() => {
    if (settingsData?.security) {
      setMfaEnabled(settingsData.security.mfaEnabled);
      setSessionTimeout(String(settingsData.security.sessionTimeout));
    }
  }, [settingsData]);

  const pwMutation = useMutation({
    mutationFn: () => meApi.changePassword(currentPw, newPw),
    onSuccess: () => {
      setCurrentPw(''); setNewPw(''); setConfirmPw('');
      setPwError('');
      onSave('Password updated successfully');
    },
    onError: (err: any) => {
      setPwError(err.response?.data?.error ?? 'Failed to update password');
    },
  });

  const secMutation = useMutation({
    mutationFn: () => meApi.updateSettings({ security: { mfaEnabled, sessionTimeout: Number(sessionTimeout) } }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['me-settings'] });
      onSave('Security settings updated');
    },
  });

  const handlePasswordSave = () => {
    setPwError('');
    if (!currentPw || !newPw) { setPwError('All password fields are required'); return; }
    if (newPw !== confirmPw) { setPwError('New passwords do not match'); return; }
    if (newPw.length < 8) { setPwError('Password must be at least 8 characters'); return; }
    pwMutation.mutate();
  };

  if (isLoading) {
    return <div className="flex items-center justify-center py-16"><Loader2 className="w-6 h-6 animate-spin text-primary" /></div>;
  }

  return (
    <div>
      <h2 className="text-xl font-bold text-foreground mb-6">Security Settings</h2>
      <div className="space-y-6">
        <div className="bg-secondary/30 border border-border rounded-xl p-5">
          <h3 className="font-semibold text-foreground mb-4">Change Password</h3>
          {pwError && <div className="mb-3 text-xs text-destructive bg-destructive/10 border border-destructive/20 rounded-lg px-3 py-2">{pwError}</div>}
          <div className="space-y-4">
            {[['Current Password', currentPw, setCurrentPw], ['New Password', newPw, setNewPw], ['Confirm New Password', confirmPw, setConfirmPw]].map(([label, val, setter]) => (
              <div key={label as string}>
                <label className="block text-sm font-medium text-muted-foreground mb-1.5">{label as string}</label>
                <div className="relative">
                  <input
                    type={showPw ? 'text' : 'password'}
                    value={val as string}
                    onChange={e => (setter as Function)(e.target.value)}
                    placeholder="••••••••"
                    className="w-full bg-input border border-border rounded-lg px-4 py-2 pr-10 text-foreground focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary"
                  />
                  {label === 'Current Password' && (
                    <button onClick={() => setShowPw(!showPw)} className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
                      {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
          {newPw && (
            <div className="space-y-1">
              <div className="flex gap-1">
                {[1, 2, 3, 4, 5].map(i => (
                  <div key={i} className={`h-1 flex-1 rounded-full ${i <= pwStrength.score ? pwStrength.color : 'bg-secondary'}`} />
                ))}
              </div>
              <p className="text-xs text-muted-foreground">Strength: <span className="font-medium text-foreground">{pwStrength.label}</span></p>
            </div>
          )}
          <div className="mt-4 flex justify-end">
            <button
              onClick={handlePasswordSave}
              disabled={pwMutation.isPending}
              className="px-5 py-2 bg-primary text-primary-foreground font-semibold rounded-lg hover:bg-primary/90 transition-all shadow-lg shadow-primary/20 text-sm disabled:opacity-50 flex items-center gap-2"
            >
              {pwMutation.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
              Update Password
            </button>
          </div>
        </div>

        <div className="flex items-center justify-between py-4 border-b border-border">
          <div>
            <div className="font-medium text-foreground">Multi-Factor Authentication</div>
            <div className="text-xs text-muted-foreground mt-0.5">{mfaEnabled ? 'MFA is enabled' : 'Enable for stronger security'}</div>
          </div>
          <button aria-label="Toggle MFA" onClick={() => setMfaEnabled(!mfaEnabled)} className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${mfaEnabled ? 'bg-primary' : 'bg-secondary border border-border'}`}>
            <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition-transform ${mfaEnabled ? 'translate-x-4' : 'translate-x-0.5'}`} />
          </button>
        </div>

        <div>
          <label className="block text-sm font-medium text-muted-foreground mb-1.5">Session Timeout</label>
          <select aria-label="Session timeout" value={sessionTimeout} onChange={e => setSessionTimeout(e.target.value)} className="w-full max-w-xs bg-input border border-border rounded-lg px-4 py-2 text-foreground focus:outline-none focus:border-primary appearance-none">
            {['1', '2', '4', '8', '24'].map(h => <option key={h} value={h}>{h} hour{h !== '1' ? 's' : ''}</option>)}
          </select>
        </div>

        <div className="flex justify-end">
          <button
            onClick={() => secMutation.mutate()}
            disabled={secMutation.isPending}
            className="px-6 py-2.5 bg-primary text-primary-foreground font-semibold rounded-lg hover:bg-primary/90 transition-all shadow-lg shadow-primary/20 disabled:opacity-50 flex items-center gap-2"
          >
            {secMutation.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
            Save Security Settings
          </button>
        </div>

        {/* Active Sessions */}
        <div className="mt-8 pt-6 border-t border-border">
          <h3 className="text-lg font-semibold text-foreground mb-4 flex items-center gap-2">
            <Monitor className="w-4 h-4 text-primary" /> Active Sessions
          </h3>
          <div className="space-y-3">
            <div className="bg-secondary/30 border border-primary/30 rounded-xl p-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
                    <Laptop className="w-5 h-5 text-primary" />
                  </div>
                  <div>
                    <div className="text-sm font-medium text-foreground flex items-center gap-2">
                      Current Session
                      <span className="text-[10px] bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 px-1.5 py-0.5 rounded-full font-semibold">Active</span>
                    </div>
                    <div className="text-xs text-muted-foreground mt-0.5">
                      {navigator.userAgent.includes('Chrome') ? 'Chrome' : navigator.userAgent.includes('Firefox') ? 'Firefox' : 'Browser'} on {navigator.platform || 'Unknown OS'}
                    </div>
                  </div>
                </div>
                <div className="text-xs text-muted-foreground">Just now</div>
              </div>
            </div>
            <div className="bg-secondary/20 border border-border rounded-xl p-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-lg bg-secondary/50 flex items-center justify-center">
                    <Smartphone className="w-5 h-5 text-muted-foreground" />
                  </div>
                  <div>
                    <div className="text-sm font-medium text-muted-foreground">API Client</div>
                    <div className="text-xs text-muted-foreground mt-0.5">REST API via API Key</div>
                  </div>
                </div>
                <button className="text-xs text-destructive hover:text-destructive/80 hover:underline">Revoke</button>
              </div>
            </div>
          </div>
          <p className="text-xs text-muted-foreground mt-3">
            <AlertTriangle className="w-3 h-3 inline mr-1 relative -top-px" />
            If you see an unrecognized session, revoke it and change your password immediately.
          </p>
        </div>
      </div>
    </div>
  );
}

function ApiKeysTab({ onSave }: { onSave: (msg: string) => void }) {
  const qc = useQueryClient();
  const [newKeyName, setNewKeyName] = useState('');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [showKey, setShowKey] = useState<string | null>(null);
  const [newRawKey, setNewRawKey] = useState<string | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ['me-api-keys'],
    queryFn: () => meApi.listApiKeys().then(r => r.data.keys),
  });

  const createMutation = useMutation({
    mutationFn: () => meApi.createApiKey(newKeyName.trim()),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ['me-api-keys'] });
      setNewRawKey(res.data.key.rawKey);
      setNewKeyName('');
      onSave(`API key "${res.data.key.name}" created — copy it now!`);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => meApi.deleteApiKey(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['me-api-keys'] }),
  });

  const copyKey = (id: string, key: string) => {
    navigator.clipboard.writeText(key);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  if (isLoading) {
    return <div className="flex items-center justify-center py-16"><Loader2 className="w-6 h-6 animate-spin text-primary" /></div>;
  }

  return (
    <div>
      <h2 className="text-xl font-bold text-foreground mb-6">API Keys</h2>

      {newRawKey && (
        <div className="mb-6 bg-emerald-500/10 border border-emerald-500/30 rounded-xl p-4">
          <p className="text-sm font-medium text-emerald-400 mb-2">New API key created — copy it now. It won't be shown again.</p>
          <div className="flex gap-2 items-center">
            <code className="flex-1 bg-[#050810] border border-border rounded-lg px-3 py-2 text-xs font-mono text-emerald-400 truncate">{newRawKey}</code>
            <button onClick={() => copyKey('new', newRawKey)} className="p-2 text-emerald-400 hover:bg-emerald-400/10 rounded-lg transition-colors">
              {copiedId === 'new' ? <CheckCheck className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
            </button>
          </div>
          <button onClick={() => setNewRawKey(null)} className="text-xs text-muted-foreground hover:text-foreground mt-2">Dismiss</button>
        </div>
      )}

      <div className="space-y-4 mb-6">
        {(data ?? []).length === 0 && (
          <div className="text-sm text-muted-foreground py-8 text-center border border-dashed border-border rounded-xl">
            No API keys yet. Create one below.
          </div>
        )}
        {(data ?? []).map(k => (
          <div key={k.id} className="bg-secondary/30 border border-border rounded-xl p-4">
            <div className="flex items-start justify-between mb-3">
              <div>
                <div className="font-semibold text-foreground">{k.name}</div>
                <div className="text-xs text-muted-foreground mt-0.5">
                  Created {new Date(k.createdAt).toLocaleDateString()} · Last used {k.lastUsedAt ? new Date(k.lastUsedAt).toLocaleDateString() : 'Never'}
                </div>
              </div>
              <button aria-label="Delete API key" onClick={() => deleteMutation.mutate(k.id)} className="p-1.5 text-muted-foreground hover:text-destructive hover:bg-destructive/10 rounded-lg transition-colors">
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
            <div className="flex gap-2 items-center mb-3">
              <code className="flex-1 bg-[#050810] border border-border rounded-lg px-3 py-2 text-xs font-mono text-green-400 truncate">
                {showKey === k.id ? `${k.keyPrefix}••••••••••••••••••••••••••` : `${k.keyPrefix}${'•'.repeat(18)}`}
              </code>
              <button onClick={() => setShowKey(showKey === k.id ? null : k.id)} className="p-2 text-muted-foreground hover:text-foreground hover:bg-secondary rounded-lg transition-colors">
                {showKey === k.id ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
            <div className="flex gap-1.5 flex-wrap">
              {(k.scopes ?? []).map(s => <span key={s} className="text-xs font-mono bg-primary/10 text-primary border border-primary/20 px-2 py-0.5 rounded">{s}</span>)}
            </div>
          </div>
        ))}
      </div>

      <div className="bg-secondary/30 border border-border rounded-xl p-4">
        <h3 className="font-semibold text-foreground text-sm mb-3">Create New Key</h3>
        <div className="flex gap-2">
          <input
            type="text"
            value={newKeyName}
            onChange={e => setNewKeyName(e.target.value)}
            placeholder="Key name (e.g. Automation Script)"
            className="flex-1 bg-input border border-border rounded-lg px-3 py-2 text-sm text-foreground focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary"
            onKeyDown={e => e.key === 'Enter' && newKeyName.trim() && createMutation.mutate()}
          />
          <button
            onClick={() => createMutation.mutate()}
            disabled={!newKeyName.trim() || createMutation.isPending}
            className="flex items-center gap-1.5 px-4 py-2 bg-primary text-white text-sm font-semibold rounded-lg hover:bg-primary/90 transition-colors disabled:opacity-50"
          >
            {createMutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
            Generate
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Data Sources Tab ────────────────────────────────────────────────────────

function DataSourcesTab() {
  const { data: stats, isLoading, refetch, isRefetching } = useQuery({
    queryKey: ['ingest-stats'],
    queryFn: () => ingestApi.stats().then(r => r.data),
    refetchInterval: 30_000,
  });

  if (isLoading) {
    return <div className="flex items-center justify-center py-16"><Loader2 className="w-6 h-6 animate-spin text-primary" /></div>;
  }

  const topSources = (stats?.bySource ?? []).sort((a, b) => b.count - a.count).slice(0, 10);
  const topSeverities = stats?.bySeverity ?? [];
  const totalLogs = stats?.total ?? 0;
  const processedPct = totalLogs > 0 ? Math.round(((stats?.processed ?? 0) / totalLogs) * 100) : 0;

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-bold text-foreground">Data Sources & Ingestion</h2>
        <button
          onClick={() => refetch()}
          disabled={isRefetching}
          className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isRefetching ? 'animate-spin' : ''}`} /> Refresh
        </button>
      </div>

      {/* Pipeline Health */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
        {[
          { label: 'Total Logs', value: totalLogs.toLocaleString(), icon: Database, color: 'text-blue-400' },
          { label: 'Last 24h', value: (stats?.last24h ?? 0).toLocaleString(), icon: Activity, color: 'text-emerald-400' },
          { label: 'Processed', value: `${processedPct}%`, icon: CheckCircle2, color: processedPct > 90 ? 'text-emerald-400' : 'text-amber-400' },
          { label: 'Unparseable', value: (stats?.unparseable ?? 0).toLocaleString(), icon: AlertTriangle, color: (stats?.unparseable ?? 0) > 0 ? 'text-red-400' : 'text-emerald-400' },
        ].map(s => (
          <div key={s.label} className="bg-secondary/30 border border-border rounded-xl p-3">
            <div className="flex items-center gap-2 mb-1">
              <s.icon className={`w-3.5 h-3.5 ${s.color}`} />
              <span className="text-xs text-muted-foreground">{s.label}</span>
            </div>
            <div className="text-lg font-bold text-foreground">{s.value}</div>
          </div>
        ))}
      </div>

      {/* Pipeline Progress */}
      <div className="mb-6">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-medium text-muted-foreground">Pipeline Processing</span>
          <span className="text-xs text-muted-foreground">{stats?.processed ?? 0} / {totalLogs} events</span>
        </div>
        <div className="h-2 bg-secondary rounded-full overflow-hidden">
          <div className="h-full bg-linear-to-r from-primary to-emerald-400 rounded-full transition-all" style={{ width: `${processedPct}%` }} />
        </div>
      </div>

      {/* Sources Table */}
      <div className="mb-6">
        <h3 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-2">
          <Server className="w-4 h-4 text-primary" /> Connected Sources
        </h3>
        {topSources.length === 0 ? (
          <div className="py-8 text-center text-sm text-muted-foreground border border-dashed border-border rounded-xl">
            No log sources ingested yet. Upload logs or configure a syslog receiver.
          </div>
        ) : (
          <div className="border border-border rounded-xl overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-secondary/30 border-b border-border">
                  <th className="px-4 py-2.5 text-left text-xs font-semibold text-muted-foreground">Source</th>
                  <th className="px-4 py-2.5 text-left text-xs font-semibold text-muted-foreground">Status</th>
                  <th className="px-4 py-2.5 text-right text-xs font-semibold text-muted-foreground">Events</th>
                  <th className="px-4 py-2.5 text-right text-xs font-semibold text-muted-foreground">Share</th>
                </tr>
              </thead>
              <tbody>
                {topSources.map(src => {
                  const pct = totalLogs > 0 ? ((src.count / totalLogs) * 100).toFixed(1) : '0';
                  return (
                    <tr key={src.source} className="border-b border-border/50 hover:bg-secondary/20 transition-colors">
                      <td className="px-4 py-2.5 font-medium text-foreground flex items-center gap-2">
                        <HardDrive className="w-3.5 h-3.5 text-muted-foreground shrink-0" />
                        {src.source}
                      </td>
                      <td className="px-4 py-2.5">
                        <span className="inline-flex items-center gap-1 text-xs text-emerald-400">
                          <Wifi className="w-3 h-3" /> Active
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-right font-mono text-xs text-foreground">{src.count.toLocaleString()}</td>
                      <td className="px-4 py-2.5 text-right">
                        <div className="flex items-center justify-end gap-2">
                          <div className="w-16 h-1.5 bg-secondary rounded-full overflow-hidden">
                            <div className="h-full bg-primary rounded-full" style={{ width: `${pct}%` }} />
                          </div>
                          <span className="text-xs text-muted-foreground w-10 text-right">{pct}%</span>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Severity Distribution */}
      {topSeverities.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-2">
            <BarChart3 className="w-4 h-4 text-primary" /> Severity Distribution
          </h3>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            {topSeverities.map(s => {
              const colors: Record<string, string> = { critical: 'text-red-400 bg-red-400/10 border-red-400/30', high: 'text-orange-400 bg-orange-400/10 border-orange-400/30', medium: 'text-amber-400 bg-amber-400/10 border-amber-400/30', low: 'text-blue-400 bg-blue-400/10 border-blue-400/30' };
              const c = colors[s.severity.toLowerCase()] ?? 'text-muted-foreground bg-secondary/30 border-border';
              return (
                <div key={s.severity} className={`border rounded-lg p-3 ${c}`}>
                  <div className="text-xs font-medium capitalize">{s.severity}</div>
                  <div className="text-lg font-bold mt-0.5">{s.count.toLocaleString()}</div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Receiver Config Info */}
      <div className="mt-6 bg-secondary/20 border border-border rounded-xl p-4">
        <h3 className="text-sm font-semibold text-foreground mb-2 flex items-center gap-2">
          <UploadCloud className="w-4 h-4 text-primary" /> Ingestion Endpoints
        </h3>
        <div className="space-y-2 text-xs">
          <div className="flex items-center justify-between py-1.5">
            <span className="text-muted-foreground">REST API</span>
            <code className="bg-[#050810] border border-border px-2.5 py-1 rounded font-mono text-emerald-400">POST /api/ingest-log</code>
          </div>
          <div className="flex items-center justify-between py-1.5 border-t border-border/30">
            <span className="text-muted-foreground">Bulk Upload</span>
            <code className="bg-[#050810] border border-border px-2.5 py-1 rounded font-mono text-emerald-400">POST /api/ingest/bulk</code>
          </div>
          <div className="flex items-center justify-between py-1.5 border-t border-border/30">
            <span className="text-muted-foreground">Raw Text</span>
            <code className="bg-[#050810] border border-border px-2.5 py-1 rounded font-mono text-emerald-400">POST /api/ingest/raw</code>
          </div>
          <div className="flex items-center justify-between py-1.5 border-t border-border/30">
            <span className="text-muted-foreground">Syslog (UDP/TCP)</span>
            <code className="bg-[#050810] border border-border px-2.5 py-1 rounded font-mono text-amber-400">Port 1514</code>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── System Info Tab ─────────────────────────────────────────────────────────

const SERVICES = [
  { name: 'PostgreSQL', desc: 'Primary data store', icon: Database, port: 5432 },
  { name: 'Redis', desc: 'Cache & pub/sub', icon: Zap, port: 6379 },
  { name: 'Syslog Receiver', desc: 'UDP/TCP log ingestion', icon: Server, port: 1514 },
  { name: 'WebSocket', desc: 'Real-time alert stream', icon: Activity, port: null },
];

function SystemTab() {
  const { data: stats, isLoading } = useQuery({
    queryKey: ['ingest-stats'],
    queryFn: () => ingestApi.stats().then(r => r.data),
    staleTime: 60_000,
  });

  return (
    <div>
      <h2 className="text-xl font-bold text-foreground mb-6">System Information</h2>

      {/* Version & Build */}
      <div className="bg-secondary/30 border border-border rounded-xl p-5 mb-6">
        <div className="flex items-start justify-between">
          <div>
            <h3 className="text-lg font-bold text-foreground">SecOps Console</h3>
            <p className="text-xs text-muted-foreground mt-1">Security Operations Center — Mini SIEM Platform</p>
          </div>
          <span className="text-xs font-mono bg-primary/10 text-primary border border-primary/20 px-2.5 py-1 rounded-full">v1.0.0</span>
        </div>
        <div className="grid grid-cols-2 gap-4 mt-4 pt-4 border-t border-border/50">
          <div>
            <div className="text-xs text-muted-foreground">Backend</div>
            <div className="text-sm font-medium text-foreground mt-0.5">Express 5 + TypeScript</div>
          </div>
          <div>
            <div className="text-xs text-muted-foreground">Frontend</div>
            <div className="text-sm font-medium text-foreground mt-0.5">React 19 + Vite</div>
          </div>
          <div>
            <div className="text-xs text-muted-foreground">Database</div>
            <div className="text-sm font-medium text-foreground mt-0.5">PostgreSQL + Drizzle ORM</div>
          </div>
          <div>
            <div className="text-xs text-muted-foreground">Detection Engine</div>
            <div className="text-sm font-medium text-foreground mt-0.5">Sigma YAML Rules</div>
          </div>
        </div>
      </div>

      {/* Connected Services */}
      <div className="mb-6">
        <h3 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-2">
          <Server className="w-4 h-4 text-primary" /> Connected Services
        </h3>
        <div className="space-y-2">
          {SERVICES.map(svc => (
            <div key={svc.name} className="flex items-center justify-between bg-secondary/20 border border-border rounded-xl p-3.5">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-lg bg-emerald-500/10 flex items-center justify-center">
                  <svc.icon className="w-4.5 h-4.5 text-emerald-400" />
                </div>
                <div>
                  <div className="text-sm font-medium text-foreground">{svc.name}</div>
                  <div className="text-xs text-muted-foreground">{svc.desc}</div>
                </div>
              </div>
              <div className="flex items-center gap-3">
                {svc.port && <span className="text-xs font-mono text-muted-foreground">:{svc.port}</span>}
                <span className="inline-flex items-center gap-1 text-xs text-emerald-400 bg-emerald-400/10 border border-emerald-400/20 px-2 py-0.5 rounded-full">
                  <Wifi className="w-3 h-3" /> Connected
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Capabilities */}
      <div className="mb-6">
        <h3 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-2">
          <Shield className="w-4 h-4 text-primary" /> Security Capabilities
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {[
            { name: 'RBAC Engine', desc: 'DB-driven roles with Redis cache', active: true },
            { name: 'Alert State Machine', desc: 'Validated status transitions', active: true },
            { name: 'Audit Logging', desc: 'Full state diff tracking', active: true },
            { name: 'Sigma Detection', desc: 'YAML-based rule matching', active: true },
            { name: 'MITRE ATT&CK', desc: 'Tactic/technique mapping', active: true },
            { name: 'Real-time Streaming', desc: 'WebSocket alert push', active: true },
          ].map(cap => (
            <div key={cap.name} className="flex items-center gap-2 bg-secondary/20 border border-border rounded-lg p-3">
              <CheckCircle2 className={`w-4 h-4 shrink-0 ${cap.active ? 'text-emerald-400' : 'text-muted-foreground'}`} />
              <div>
                <div className="text-xs font-medium text-foreground">{cap.name}</div>
                <div className="text-[10px] text-muted-foreground">{cap.desc}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Data Summary */}
      {!isLoading && stats && (
        <div className="bg-secondary/20 border border-border rounded-xl p-4">
          <h3 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-2">
            <BarChart3 className="w-4 h-4 text-primary" /> Data Summary
          </h3>
          <div className="grid grid-cols-3 gap-3">
            <div className="text-center">
              <div className="text-xl font-bold text-foreground">{(stats.total ?? 0).toLocaleString()}</div>
              <div className="text-[10px] text-muted-foreground">Total Events</div>
            </div>
            <div className="text-center">
              <div className="text-xl font-bold text-foreground">{(stats.bySource ?? []).length}</div>
              <div className="text-[10px] text-muted-foreground">Log Sources</div>
            </div>
            <div className="text-center">
              <div className="text-xl font-bold text-foreground">{(stats.last24h ?? 0).toLocaleString()}</div>
              <div className="text-[10px] text-muted-foreground">Events (24h)</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState<Tab>('profile');
  const [toast, setToast] = useState<string | null>(null);
  const showToast = (msg: string) => { setToast(msg); setTimeout(() => setToast(null), 3500); };

  return (
    <>
      {toast && <Toast msg={toast} />}
      <div className="flex flex-col gap-6 max-w-4xl">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-foreground flex items-center gap-3">
            <Settings className="w-8 h-8 text-primary" /> Settings
          </h1>
          <p className="text-muted-foreground mt-1">Configure your console preferences and account settings.</p>
        </div>

        <div className="bg-card border border-border rounded-xl shadow-lg overflow-hidden">
          <div className="flex flex-col md:flex-row">
            <div className="p-5 md:w-56 border-b md:border-b-0 md:border-r border-border bg-secondary/20">
              <nav className="flex md:flex-col gap-1">
                {TAB_SECTIONS.map((section, si) => (
                  <React.Fragment key={section.section}>
                    {si > 0 && <div className="hidden md:block h-px bg-border my-2" />}
                    <div className="hidden md:block text-[10px] font-semibold text-muted-foreground uppercase tracking-wider px-3 py-1">{section.section}</div>
                    {section.tabs.map(tab => (
                      <button
                        key={tab.id}
                        onClick={() => setActiveTab(tab.id)}
                        className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${activeTab === tab.id ? 'bg-primary/10 text-primary shadow-sm border border-primary/20' : 'text-muted-foreground hover:bg-secondary hover:text-foreground'}`}
                      >
                        <tab.icon className="w-4 h-4 shrink-0" /> {tab.label}
                      </button>
                    ))}
                  </React.Fragment>
                ))}
              </nav>
            </div>
            <div className="p-8 flex-1 min-w-0">
              {activeTab === 'profile' && <ProfileTab onSave={showToast} />}
              {activeTab === 'notifications' && <NotificationsTab onSave={showToast} />}
              {activeTab === 'security' && <SecurityTab onSave={showToast} />}
              {activeTab === 'apikeys' && <ApiKeysTab onSave={showToast} />}
              {activeTab === 'datasources' && <DataSourcesTab />}
              {activeTab === 'system' && <SystemTab />}
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
