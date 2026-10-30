const form = document.querySelector('#accountForm');
const loginTab = document.querySelector('#loginTab');
const registerTab = document.querySelector('#registerTab');
const title = document.querySelector('#authTitle');
const intro = document.querySelector('#authIntro');
const submit = document.querySelector('#submitAccount');
const status = document.querySelector('#authStatus');
let mode = 'login';

function setMode(next) {
  mode = next;
  const registering = mode === 'register';
  loginTab.classList.toggle('is-active', !registering);
  registerTab.classList.toggle('is-active', registering);
  loginTab.setAttribute('aria-selected', String(!registering));
  registerTab.setAttribute('aria-selected', String(registering));
  title.textContent = registering ? 'Start your rhythm.' : 'Welcome back.';
  intro.textContent = registering ? 'Create a FitTrack account and keep your daily goals close.' : 'Sign in to your FitTrack account to continue.';
  submit.textContent = registering ? 'Create account' : 'Sign in';
  document.querySelector('#password').autocomplete = registering ? 'new-password' : 'current-password';
  status.textContent = '';
  status.className = 'auth-status';
}
function showStatus(message, kind = 'error') {
  status.textContent = message;
  status.className = `auth-status ${kind}`;
}
async function submitAccount(event) {
  event.preventDefault();
  if (!form.reportValidity()) return;
  submit.disabled = true;
  submit.textContent = mode === 'register' ? 'Creating…' : 'Signing in…';
  showStatus('');
  const data = Object.fromEntries(new FormData(form).entries());
  try {
    const response = await fetch(`/api/auth/${mode}`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.message || 'Could not complete this request.');
    showStatus(mode === 'register' ? 'Account created. Opening your dashboard…' : 'Signed in. Opening your dashboard…', 'success');
    setTimeout(() => { window.location.href = '/'; }, 350);
  } catch (error) {
    showStatus(error.message || 'Could not complete this request.');
    submit.disabled = false;
    submit.textContent = mode === 'register' ? 'Create account' : 'Sign in';
  }
}
loginTab.addEventListener('click', () => setMode('login'));
registerTab.addEventListener('click', () => setMode('register'));
form.addEventListener('submit', submitAccount);
