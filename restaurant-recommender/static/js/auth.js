import { sendPasswordResetEmail } from 'https://www.gstatic.com/firebasejs/10.12.0/firebase-auth.js';
window.authSendPasswordReset = async function() {
  let email = null;
  // Try to get email from user context if available
  if (window.userEmail) {
    email = window.userEmail;
  } else {
    // Try to get from login form as fallback
    const emailInput = document.getElementById('login-email');
    if (emailInput) email = emailInput.value;
  }
  if (!email) {
    alert('No email found for password reset.');
    return;
  }
  try {
    await sendPasswordResetEmail(auth, email);
    alert('Password reset email sent! Check your inbox.');
  } catch (err) {
    alert(err.message);
  }
};
// Set userEmail from template if available
if (window.userEmail === undefined && typeof USER_EMAIL_FROM_TEMPLATE !== 'undefined') {
  window.userEmail = USER_EMAIL_FROM_TEMPLATE;
}
// Firebase Web SDK v9+ modular import
import { initializeApp } from 'https://www.gstatic.com/firebasejs/10.12.0/firebase-app.js';
import {
  getAuth, createUserWithEmailAndPassword, signInWithEmailAndPassword,
  sendSignInLinkToEmail, isSignInWithEmailLink, signInWithEmailLink, onAuthStateChanged
} from 'https://www.gstatic.com/firebasejs/10.12.0/firebase-auth.js';

// TODO: Replace with your Firebase config
const firebaseConfig = {
  apiKey: 'AIzaSyDvayNH8i2EQjEfQ5uOPybr5UYCw8T8SqQ',
  authDomain: 'nourishnet-c3597.firebaseapp.com',
  projectId: 'nourishnet-c3597',
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);

window.authRegisterWithPassword = async function() {
  const username = document.getElementById('register-username').value;
  const email = document.getElementById('register-email').value;
  const password = document.getElementById('register-password').value;
  const role = document.getElementById('register-role').value;
  try {
    const userCred = await createUserWithEmailAndPassword(auth, email, password);
    const idToken = await userCred.user.getIdToken();
    const firebase_uid = userCred.user.uid;
    console.log('[DEBUG] Register: Firebase user created, UID:', firebase_uid);
    // Always set session cookie first
    await sessionLogin(idToken);
    // Then send registration info to backend, including firebase_uid
    const res = await fetch('/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        username,
        email,
        role,
        firebase_uid
      })
    });
    console.log('[DEBUG] Register: /register response', res);
    if (res.redirected) {
      window.location = res.url;
    }
  } catch (err) {
    console.error('[DEBUG] Register error:', err);
    alert(err.message);
  }
};

window.authLoginWithPassword = async function() {
  const email = document.getElementById('login-email').value;
  const password = document.getElementById('login-password').value;
  try {
    const userCred = await signInWithEmailAndPassword(auth, email, password);
    const idToken = await userCred.user.getIdToken();
    const firebase_uid = userCred.user.uid;
    console.log('[DEBUG] Login: Firebase user signed in, UID:', firebase_uid);
    // Always set session cookie first
    await sessionLogin(idToken);
    // Then send UID to backend to get role and redirect
    const res = await fetch('/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        email,
        firebase_uid
      })
    });
    console.log('[DEBUG] Login: /login response', res);
    if (res.redirected) {
      window.location = res.url;
    }
  } catch (err) {
    console.error('[DEBUG] Login error:', err);
    alert(err.message);
  }
};

window.authLoginWithEmailLink = async function() {
  const email = document.getElementById('login-email').value;
  const actionCodeSettings = {
    url: window.location.origin + '/login',
    handleCodeInApp: true
  };
  try {
    await sendSignInLinkToEmail(auth, email, actionCodeSettings);
    window.localStorage.setItem('emailForSignIn', email);
    alert('Check your email for the sign-in link.');
  } catch (err) {
    alert(err.message);
  }
};

async function sessionLogin(idToken) {
  try {
    console.log('[DEBUG] sessionLogin called with idToken:', !!idToken);
    const res = await fetch('/sessionLogin', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ idToken })
    });
    console.log('[DEBUG] sessionLogin /sessionLogin response', res);
    if (res.status === 204) {
      window.location = '/dashboard';
    } else {
      const data = await res.json();
      console.error('[DEBUG] sessionLogin failed:', data);
      alert('Session login failed: ' + (data.error || res.status));
    }
  } catch (err) {
    console.error('[DEBUG] sessionLogin error:', err);
    alert('Session login error: ' + err.message);
  }
}

window.authLogout = async function() {
  await fetch('/sessionLogout', { method: 'POST' });
  window.location = '/login';
};

// Handle email link sign-in
if (isSignInWithEmailLink(auth, window.location.href)) {
  let email = window.localStorage.getItem('emailForSignIn');
  if (!email) {
    email = window.prompt('Please provide your email for confirmation');
  }
  signInWithEmailLink(auth, email, window.location.href)
    .then(async (result) => {
      window.localStorage.removeItem('emailForSignIn');
      const idToken = await result.user.getIdToken();
      await sessionLogin(idToken);
    })
    .catch((err) => {
      alert(err.message);
    });
}
