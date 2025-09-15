import { sendPasswordResetEmail } from 'https://www.gstatic.com/firebasejs/10.12.0/firebase-auth.js';
window.authSendPasswordReset = async function() {
  const email = document.getElementById('login-email').value;
  if (!email) {
    alert('Please enter your email address to reset your password.');
    return;
  }
  try {
    await sendPasswordResetEmail(auth, email);
    alert('Password reset email sent! Check your inbox.');
  } catch (err) {
    alert(err.message);
  }
};
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
  const email = document.getElementById('register-email').value;
  const password = document.getElementById('register-password').value;
  try {
    const userCred = await createUserWithEmailAndPassword(auth, email, password);
    const idToken = await userCred.user.getIdToken();
    await sessionLogin(idToken);
  } catch (err) {
    alert(err.message);
  }
};

window.authLoginWithPassword = async function() {
  const email = document.getElementById('login-email').value;
  const password = document.getElementById('login-password').value;
  try {
    const userCred = await signInWithEmailAndPassword(auth, email, password);
    const idToken = await userCred.user.getIdToken();
    await sessionLogin(idToken);
  } catch (err) {
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
  const res = await fetch('/sessionLogin', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ idToken })
  });
  if (res.status === 204) {
    window.location = '/dashboard';
  } else {
    alert('Session login failed');
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
