import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
})

// Uncomment this when used for github Pages, else use above
//export default defineConfig({
//  plugins: [react()],
//  base: '/minisiem/',
//})