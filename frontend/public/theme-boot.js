/* Applies the stored theme choice before the app renders, so the light theme
   does not flash up on a dark-mode machine.

   Deliberately a file of its own rather than an inline <script>: inline code
   would need 'unsafe-inline' in the Content-Security-Policy - which is the
   very thing the policy exists to prevent - or a hash that silently stops
   matching the next time this code is touched. */
try {
  var stored = localStorage.getItem('permitra_theme')
  if (stored === 'light' || stored === 'dark') {
    document.documentElement.setAttribute('data-theme', stored)
  }
} catch (e) {
  /* localStorage can be unavailable (private mode, blocked cookies) - the app
     then simply starts in the system theme. */
}
