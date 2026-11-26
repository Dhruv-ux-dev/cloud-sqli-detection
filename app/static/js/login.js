(() => {
  const form = document.getElementById("form");
  const error = document.getElementById("error");
  const submit = document.getElementById("submit");

  api("/api/config").then((cfg) => {
    const text = {
      aws: "Protected by AWS WAF and the application filter.",
      emulated: "Running locally: the application emulates AWS WAF.",
      off: "Filtering is switched off for the controlled demo.",
    }[cfg.waf_mode];
    if (text) document.getElementById("mode").textContent = text;
  }).catch(() => {});

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    error.hidden = true;
    const username = form.username.value.trim();
    const password = form.password.value;
    if (!username || !password) {
      error.textContent = "Enter your username and password.";
      error.hidden = false;
      return;
    }
    submit.disabled = true;
    submit.textContent = "Signing in";
    try {
      const res = await api("/api/login", { method: "POST", body: { username, password } });
      window.location.assign(res.home);
    } catch (err) {
      error.textContent = err.message;
      error.hidden = false;
      submit.disabled = false;
      submit.textContent = "Sign in";
    }
  });
})();
