import React, { useEffect, useMemo } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { auth } from '../lib/auth';
import { useDocumentTitle } from '../lib/useDocumentTitle';

const AuthCallback = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  useDocumentTitle('Authentication');

  const { status, shouldRedirect, redirectPath } = useMemo(() => {
    const accessToken = searchParams.get('access_token');
    const refreshToken = searchParams.get('refresh_token');
    const error = searchParams.get('error');

    if (error) {
      return { status: 'Authentication failed. Please try again.', shouldRedirect: true, redirectPath: '/join-us' };
    }

    if (accessToken) {
      auth.setTokens(accessToken, refreshToken);
      return { status: 'Access granted. Redirecting...', shouldRedirect: true, redirectPath: '/home' };
    }

    return { status: 'Invalid authentication response.', shouldRedirect: true, redirectPath: '/join-us' };
  }, [searchParams]);

  useEffect(() => {
    if (shouldRedirect) {
      const delay = redirectPath === '/home' ? 500 : 2000;
      const timer = setTimeout(() => navigate(redirectPath, { replace: true }), delay);
      return () => clearTimeout(timer);
    }
  }, [shouldRedirect, redirectPath, navigate]);

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
