<script setup lang="ts">
import { ref, computed } from 'vue'
import { authApi, setToken, setStoredUser } from '@/api/client'

const emit = defineEmits<{ (e: 'auth-success'): void }>()

const mode = ref<'login' | 'register'>('login')

// Login fields
const loginEmail = ref('')
const loginPassword = ref('')

// Register fields
const regOrgName = ref('')
const regName = ref('')
const regEmail = ref('')
const regPassword = ref('')
const regConfirm = ref('')

const loading = ref(false)
const error = ref('')

const isLogin = computed(() => mode.value === 'login')

async function handleLogin() {
  error.value = ''
  if (!loginEmail.value || !loginPassword.value) {
    error.value = 'Email dan password wajib diisi'
    return
  }
  loading.value = true
  try {
    const result = await authApi.login(loginEmail.value, loginPassword.value)
    setToken(result.token)
    setStoredUser(result.user)
    emit('auth-success')
  } catch (e: any) {
    error.value = e.message || 'Login gagal. Periksa email dan password Anda.'
  } finally {
    loading.value = false
  }
}

async function handleRegister() {
  error.value = ''
  if (!regOrgName.value || !regName.value || !regEmail.value || !regPassword.value) {
    error.value = 'Semua field wajib diisi'
    return
  }
  if (regPassword.value.length < 6) {
    error.value = 'Password minimal 6 karakter'
    return
  }
  if (regPassword.value !== regConfirm.value) {
    error.value = 'Konfirmasi password tidak cocok'
    return
  }
  loading.value = true
  try {
    const result = await authApi.register(regOrgName.value, regName.value, regEmail.value, regPassword.value)
    setToken(result.token)
    setStoredUser(result.user)
    emit('auth-success')
  } catch (e: any) {
    error.value = e.message || 'Registrasi gagal. Coba lagi.'
  } finally {
    loading.value = false
  }
}

function toggleMode() {
  mode.value = mode.value === 'login' ? 'register' : 'login'
  error.value = ''
}
</script>

<template>
  <div class="min-h-screen flex items-center justify-center p-4 bg-cyber-bg">
    <!-- Animated background -->
    <div class="fixed inset-0 overflow-hidden pointer-events-none opacity-20">
      <div class="absolute -top-40 -left-40 w-96 h-96 bg-cyber-accent/20 rounded-full blur-3xl animate-pulse"></div>
      <div class="absolute -bottom-40 -right-40 w-96 h-96 bg-purple-500/20 rounded-full blur-3xl animate-pulse" style="animation-delay: 1s;"></div>
    </div>

    <div class="relative w-full max-w-md">
      <!-- Logo -->
      <div class="flex flex-col items-center mb-8">
        <svg viewBox="0 0 32 32" class="w-12 h-12 mb-3">
          <path d="M16 4 L26 9 V16 C26 21 22 25 16 27 C10 25 6 21 6 16 V9 Z" stroke="#00d9ff" stroke-width="1.5" fill="none"/>
          <circle cx="16" cy="15" r="3" fill="#00d9ff" opacity="0.8"/>
        </svg>
        <h1 class="text-xl font-bold tracking-tight text-cyber-text">CyberWatch IDS</h1>
        <p class="text-sm text-cyber-textmuted mt-1">Security Monitoring &amp; Intrusion Detection</p>
      </div>

      <!-- Card -->
      <div class="bg-cyber-card border border-cyber-border rounded-xl p-6 shadow-2xl">
        <!-- Tab toggle -->
        <div class="flex gap-2 p-1 bg-cyber-bg rounded-lg mb-6">
          <button
            @click="mode = 'login'; error = ''"
            :class="[
              'flex-1 py-2 rounded-md text-sm font-medium transition-colors',
              isLogin ? 'bg-cyber-accent text-white' : 'text-cyber-textdim hover:text-cyber-text'
            ]"
          >
            Masuk
          </button>
          <button
            @click="mode = 'register'; error = ''"
            :class="[
              'flex-1 py-2 rounded-md text-sm font-medium transition-colors',
              !isLogin ? 'bg-cyber-accent text-white' : 'text-cyber-textdim hover:text-cyber-text'
            ]"
          >
            Daftar Organisasi
          </button>
        </div>

        <!-- Error -->
        <div v-if="error" class="mb-4 px-3 py-2 bg-red-500/10 border border-red-500/30 rounded-lg text-sm text-red-400">
          {{ error }}
        </div>

        <!-- Login Form -->
        <form v-if="isLogin" @submit.prevent="handleLogin" class="space-y-4">
          <div>
            <label class="block text-xs font-medium text-cyber-textdim mb-1.5">Email</label>
            <input
              v-model="loginEmail"
              type="email"
              placeholder="admin@perusahaan.com"
              class="w-full px-3 py-2.5 bg-cyber-bg border border-cyber-border rounded-lg text-sm text-cyber-text placeholder-cyber-textmuted/50 focus:border-cyber-accent focus:outline-none transition-colors"
              required
            />
          </div>
          <div>
            <label class="block text-xs font-medium text-cyber-textdim mb-1.5">Password</label>
            <input
              v-model="loginPassword"
              type="password"
              placeholder="••••••••"
              class="w-full px-3 py-2.5 bg-cyber-bg border border-cyber-border rounded-lg text-sm text-cyber-text placeholder-cyber-textmuted/50 focus:border-cyber-accent focus:outline-none transition-colors"
              required
            />
          </div>
          <button
            type="submit"
            :disabled="loading"
            class="w-full py-2.5 bg-cyber-accent hover:bg-cyber-accent/90 text-white rounded-lg text-sm font-semibold transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {{ loading ? 'Memproses...' : 'Masuk' }}
          </button>
        </form>

        <!-- Register Form -->
        <form v-else @submit.prevent="handleRegister" class="space-y-4">
          <div>
            <label class="block text-xs font-medium text-cyber-textdim mb-1.5">Nama Organisasi</label>
            <input
              v-model="regOrgName"
              type="text"
              placeholder="PT. Maju Sejahtera"
              class="w-full px-3 py-2.5 bg-cyber-bg border border-cyber-border rounded-lg text-sm text-cyber-text placeholder-cyber-textmuted/50 focus:border-cyber-accent focus:outline-none transition-colors"
              required
            />
          </div>
          <div>
            <label class="block text-xs font-medium text-cyber-textdim mb-1.5">Nama Lengkap</label>
            <input
              v-model="regName"
              type="text"
              placeholder="John Doe"
              class="w-full px-3 py-2.5 bg-cyber-bg border border-cyber-border rounded-lg text-sm text-cyber-text placeholder-cyber-textmuted/50 focus:border-cyber-accent focus:outline-none transition-colors"
              required
            />
          </div>
          <div>
            <label class="block text-xs font-medium text-cyber-textdim mb-1.5">Email</label>
            <input
              v-model="regEmail"
              type="email"
              placeholder="admin@perusahaan.com"
              class="w-full px-3 py-2.5 bg-cyber-bg border border-cyber-border rounded-lg text-sm text-cyber-text placeholder-cyber-textmuted/50 focus:border-cyber-accent focus:outline-none transition-colors"
              required
            />
          </div>
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="block text-xs font-medium text-cyber-textdim mb-1.5">Password</label>
              <input
                v-model="regPassword"
                type="password"
                placeholder="Min. 6 karakter"
                class="w-full px-3 py-2.5 bg-cyber-bg border border-cyber-border rounded-lg text-sm text-cyber-text placeholder-cyber-textmuted/50 focus:border-cyber-accent focus:outline-none transition-colors"
                required
              />
            </div>
            <div>
              <label class="block text-xs font-medium text-cyber-textdim mb-1.5">Konfirmasi</label>
              <input
                v-model="regConfirm"
                type="password"
                placeholder="Ulangi password"
                class="w-full px-3 py-2.5 bg-cyber-bg border border-cyber-border rounded-lg text-sm text-cyber-text placeholder-cyber-textmuted/50 focus:border-cyber-accent focus:outline-none transition-colors"
                required
              />
            </div>
          </div>
          <button
            type="submit"
            :disabled="loading"
            class="w-full py-2.5 bg-cyber-accent hover:bg-cyber-accent/90 text-white rounded-lg text-sm font-semibold transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {{ loading ? 'Membuat akun...' : 'Daftar Sekarang' }}
          </button>
        </form>

        <!-- Toggle -->
        <p class="text-center text-xs text-cyber-textmuted mt-5">
          <span v-if="isLogin">Belum punya akun? </span>
          <span v-else>Sudah punya akun? </span>
          <button @click="toggleMode" class="text-cyber-accent hover:underline font-medium">
            {{ isLogin ? 'Daftar di sini' : 'Masuk di sini' }}
          </button>
        </p>
      </div>

      <p class="text-center text-xs text-cyber-textmuted mt-4">
        Dengan mendaftar, Anda mendapatkan akun organisasi gratis dengan 5 user
      </p>
    </div>
  </div>
</template>
