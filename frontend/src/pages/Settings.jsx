import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Header from '../components/Header';
import GitIntegration from '../components/GitIntegration';
import { auth } from '../lib/auth';
import { useDocumentTitle } from '../lib/useDocumentTitle';
import { apiRequest } from '../lib/apiClient';

const Settings = () => {
  const [user, setUser] = useState(null);
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();
  useDocumentTitle('Settings');

  useEffect(() => {
    const loadUser = async () => {
      setIsLoading(true);
      try {
        const response = await apiRequest('/api/v1/auth/me');
        const data = await response.json();
        setUser(data);
        setName(data.name || '');
        setEmail(data.email || '');
      } catch (err) {
        setError(err.message === 'AUTHENTICATION_REQUIRED' ? 'Session expired.' : 'Failed to load profile.');
      }
      setIsLoading(false);
    };
    loadUser();
  }, []);

  const handleSave = async (e) => {
    e.preventDefault();
    setIsSaving(true);
    setMessage('');
    setError('');
    try {
      await apiRequest('/api/v1/auth/me', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email }),
      });
      setMessage('Profile updated successfully.');
    } catch (err) {
      setError(err.message || 'Failed to update profile.');
    }
    setIsSaving(false);
  };

  const handleDeleteAccount = async () => {
    if (!window.confirm('Are you sure you want to delete your account? This action cannot be undone.')) return;
    try {
      await apiRequest('/api/v1/auth/account', { method: 'DELETE' });
      auth.clearTokens();
      navigate('/');
    } catch {
      setError('Failed to delete account.');
    }
  };

  const handleSignOut = () => {
    auth.clearTokens();
    navigate('/');
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-[#050505] font-lambo text-white">
        <Header />
        <main className="relative px-5 pt-28 md:px-10">
          <div className="chamfer-panel mx-auto max-w-2xl border border-white/10 bg-white/[0.02] p-8 text-[10px] tracking-[0.3em] text-lambo-ash">
            Loading profile...
          </div>
        </main>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#050505] font-lambo text-white">
      <Header />
      <main className="relative overflow-hidden px-5 pb-16 pt-28 md:px-10">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_top_right,rgba(255,193,7,0.05),transparent_28%)]" />
        <section className="relative mx-auto max-w-2xl space-y-6">
          <div>
            <p className="text-[10px] font-bold tracking-[0.4em] text-lambo-gold">// Account Settings</p>
            <h1 className="mt-3 text-3xl font-black tracking-[-0.03em] text-lambo-white">Profile</h1>
          </div>

          {message && (
            <div className="chamfer-panel border border-green-500/30 bg-green-500/10 px-5 py-4 text-[10px] font-bold tracking-[0.22em] text-green-500">{message}</div>
          )}
          {error && (
            <div className="chamfer-panel border border-red-500/30 bg-red-500/10 px-5 py-4 text-[10px] font-bold tracking-[0.22em] text-red-500">{error}</div>
          )}

          <form onSubmit={handleSave} className="chamfer-panel border border-lambo-gold/20 bg-[#0d0d0d] p-8 space-y-6">
            <div>
              <label className="text-[10px] font-bold tracking-[0.3em] text-lambo-gold block mb-3">Name</label>
              <input type="text" value={name} onChange={(e) => setName(e.target.value)}
                className="w-full border border-white/10 bg-black/40 px-4 py-3 text-sm text-lambo-white focus:border-lambo-gold/40 focus:outline-none" />
            </div>
            <div>
              <label className="text-[10px] font-bold tracking-[0.3em] text-lambo-gold block mb-3">Email</label>
              <input type="email" value={email} onChange={(e) => setEmail(e.target.value)}
                className="w-full border border-white/10 bg-black/40 px-4 py-3 text-sm text-lambo-white focus:border-lambo-gold/40 focus:outline-none" />
            </div>
            <div>
              <label className="text-[10px] font-bold tracking-[0.3em] text-lambo-ash block mb-3">Provider</label>
              <p className="text-sm text-lambo-white">{user?.provider || 'email'}</p>
            </div>
            <div>
              <label className="text-[10px] font-bold tracking-[0.3em] text-lambo-ash block mb-3">Member Since</label>
              <p className="text-sm text-lambo-white">{user?.created_at ? new Date(user.created_at).toLocaleDateString() : 'Unknown'}</p>
            </div>
            <button type="submit" disabled={isSaving}
              className="chamfer-button w-full border border-lambo-gold/30 bg-lambo-gold/10 px-4 py-4 text-[10px] font-bold tracking-[0.2em] text-lambo-gold transition-colors hover:bg-lambo-gold/20 disabled:opacity-50">
              {isSaving ? 'Saving...' : 'Save Changes'}
            </button>
          </form>

          <GitIntegration />

          <div className="chamfer-panel border border-white/10 bg-[#0d0d0d] p-8 flex flex-col gap-4 sm:flex-row sm:justify-between">
            <button type="button" onClick={handleSignOut}
              className="chamfer-button border border-white/10 bg-white/5 px-6 py-3 text-[10px] font-bold tracking-[0.2em] text-lambo-ash transition-colors hover:border-lambo-gold/40 hover:text-lambo-gold">
              Sign Out
            </button>
            <button type="button" onClick={handleDeleteAccount}
              className="chamfer-button border border-red-500/30 bg-red-500/10 px-6 py-3 text-[10px] font-bold tracking-[0.2em] text-red-400 transition-colors hover:bg-red-500/20">
              Delete Account
            </button>
          </div>
        </section>
      </main>
    </div>
  );
};

export default Settings;
