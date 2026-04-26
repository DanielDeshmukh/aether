import { useEffect } from 'react';

const APP_NAME = 'AETHER';

export const useDocumentTitle = (pageTitle) => {
  useEffect(() => {
    document.title = pageTitle ? `${pageTitle} | ${APP_NAME}` : APP_NAME;
  }, [pageTitle]);
};
