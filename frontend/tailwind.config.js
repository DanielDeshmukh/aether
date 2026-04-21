/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'lambo-black': '#000000',
        'lambo-gold': '#FFC000',
        'lambo-gold-dark': '#917300',
        'lambo-white': '#FFFFFF',
        'lambo-charcoal': '#202020',
        'lambo-ash': '#7D7D7D',
        'lambo-cyan': '#29ABE2',
      },
      fontFamily: {
        lambo: ['Inter', 'sans-serif'],
      }
    },
  },
  plugins: [],
}
