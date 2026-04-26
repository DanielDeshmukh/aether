const rawApiUrl = import.meta.env.VITE_API_URL?.trim() ?? '';

const trimTrailingSlash = (value) => value.replace(/\/+$/, '');

export const getApiBaseUrl = () => {
  if (!rawApiUrl) {
    return '';
  }

  return trimTrailingSlash(rawApiUrl);
};

export const buildApiUrl = (path) => {
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  const baseUrl = getApiBaseUrl();
  return baseUrl ? `${baseUrl}${normalizedPath}` : normalizedPath;
};

export const buildWsUrl = (path) => {
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  const baseUrl = getApiBaseUrl();

  if (!baseUrl) {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${protocol}//${window.location.host}${normalizedPath}`;
  }

  if (baseUrl.startsWith('http://')) {
    return `ws://${baseUrl.slice('http://'.length)}${normalizedPath}`;
  }

  if (baseUrl.startsWith('https://')) {
    return `wss://${baseUrl.slice('https://'.length)}${normalizedPath}`;
  }

  return baseUrl ? `${baseUrl}${normalizedPath}` : normalizedPath;
};
