import React, { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { auth } from '../lib/auth';
import { useDocumentTitle } from '../lib/useDocumentTitle';

const AuthCallback = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [status, setStatus] = useState('Processing...');
  useDocumentTitle('Authentication');

  useEffect(() => {
    const accessToken = searchParams.get('access_token');
    const refreshToken = searchParams.get('refresh_token');
    const error = searchParams.get('error');

    if (error) {
      setStatus('Authentication failed. Please try again.');
      setTimeout(() => navigate('/join-us', { replace: true }), 2000);
      return;
    }

    if (accessToken) {
      auth.setTokens(accessToken, refreshToken);
      setStatus('Access granted. Redirecting...');
      setTimeout(() => navigate('/home', { replace: true }), 500);
      return;
    }

    setStatus('Invalid authentication response.');
    setTimeout(() => navigate('/join-us', { replace: true }), 2000);
  }, [searchParams, navigate]);

  return (
    <section className="min-h-screen bg-lambo-black flex items-center justify-center px-5 font-mono">
      <div className="text-center">
        <div className="flex justify-center items-center gap-3 mb-6">
          <div className="w-10 h-[1px] bg-lambo-gold"></div>
          <span className="text-[10px] text-lambo-gold tracking-[0.4em] uppercase font-black">
            AETHER
          </span>
          <div className="w-10 h-[1px] bg-lambo-gold"></div>
        </div>
        <div className="flex items-center justify-center gap-3 mb-6">
          <div className="w-3 h-3 border-2 border-lambo-gold/30 border-t-lambo-gold rounded-full animate-spin" />
          <p className="text-lambo-ash text-xs uppercase tracking-widest">{status}</p>
        </div>
      </div>
    </section>
  );
};

export default AuthCallback;
