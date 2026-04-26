import path from 'node:path'
import { defineConfig, loadEnv } from 'vite'
import react, { reactCompilerPreset } from '@vitejs/plugin-react'
import babel from '@rolldown/plugin-babel'

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  const envDir = path.resolve(__dirname, '..')
  const env = loadEnv(mode, envDir, '')
  const requiredEnvVars = ['VITE_SUPABASE_URL', 'VITE_SUPABASE_ANON_KEY']
  const missingEnvVars = requiredEnvVars.filter((key) => !env[key]?.trim())

  if (missingEnvVars.length > 0) {
    throw new Error(
      `Missing required environment variables in ${path.join(envDir, '.env')}: ${missingEnvVars.join(', ')}`
    )
  }

  return {
    envDir,
    plugins: [
      react(),
      babel({ presets: [reactCompilerPreset()] })
    ],
    server: {
      proxy: {
        '/api': 'http://localhost:8000',
        '/ws': {
          target: 'ws://localhost:8000',
          ws: true,
        },
      },
    },
  }
})
