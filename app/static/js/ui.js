// Petits comportements d'interface, dans un fichier séparé pour respecter la CSP
// (script-src 'self' : aucun JavaScript inline n'est autorisé).
document.addEventListener("click", function (e) {
  var btn = e.target.closest("[data-toggle-pwd]");
  if (!btn) return;
  var el = document.getElementById(btn.getAttribute("data-toggle-pwd"));
  el.type = el.type === "password" ? "text" : "password";
  btn.classList.toggle("shown");
});

// Demande une confirmation avant les actions sensibles (formulaires data-confirm)
document.addEventListener("submit", function (e) {
  var msg = e.target.getAttribute("data-confirm");
  if (msg && !window.confirm(msg)) e.preventDefault();
});
