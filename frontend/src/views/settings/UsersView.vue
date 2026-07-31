<script setup lang="ts">
import { ref, onMounted, computed, watch } from 'vue'
import { useTenantStore } from '@/stores/tenant'
import { useToastStore } from '@/stores/toast'
import { useAuthStore } from '@/stores/auth'
import apiClient from '@/api/client'
import AppDialog from '@/components/AppDialog.vue'

interface TenantUser {
  id: number
  email: string
  username: string
  full_name: string | null
  role: string
  is_active: boolean
  membership_active: boolean
  last_login: string | null
  created_at: string
}

interface Invitation {
  id: number
  email: string
  role: string
  inviter_name: string | null
  expires_at: string
  created_at: string
}

const tenantStore = useTenantStore()
const toast = useToastStore()
const authStore = useAuthStore()
const tid = computed(() => tenantStore.currentTenantId)

// Make it explicit WHICH tenant's users are being managed; superusers can
// switch tenant inline (the tid watcher reloads the list).
const isSuperuser = computed(() => !!authStore.currentUser?.is_superuser)
const currentTenantName = computed(() => tenantStore.currentTenant?.name ?? '')
function switchTenant(event: Event) {
  const id = parseInt((event.target as HTMLSelectElement).value, 10)
  if (!isNaN(id)) tenantStore.selectTenant(id)
}

const users = ref<TenantUser[]>([])
const invitations = ref<Invitation[]>([])
const isLoading = ref(true)

// Create user modal state
const showCreateModal = ref(false)
const createEmail = ref('')
const createUsername = ref('')
const createPassword = ref('')
const createFullName = ref('')
const createRole = ref('analyst')
const isCreating = ref(false)

// Invite modal state
const showInviteModal = ref(false)
const inviteEmail = ref('')
const inviteRole = ref('analyst')
const isInviting = ref(false)

// Edit role state
const editingUserId = ref<number | null>(null)
const editingRole = ref('')

const roles = ['viewer', 'analyst', 'admin']

function getRoleBadgeClass(role: string): string {
  switch (role) {
    case 'owner': return 'bg-purple-100 text-purple-700 dark:bg-purple-900/20 dark:text-purple-400'
    case 'admin': return 'bg-red-100 text-red-700 dark:bg-red-900/20 dark:text-red-400'
    case 'analyst': return 'bg-blue-100 text-blue-700 dark:bg-blue-900/20 dark:text-blue-400'
    case 'viewer': return 'bg-gray-100 text-gray-700 dark:bg-gray-700/30 dark:text-gray-400'
    default: return 'bg-gray-100 text-gray-700 dark:bg-gray-700/30 dark:text-gray-400'
  }
}

async function fetchData() {
  if (!tid.value) return
  isLoading.value = true

  try {
    const [usersRes, invitationsRes] = await Promise.all([
      apiClient.get(`/api/v1/tenants/${tid.value}/users`),
      apiClient.get(`/api/v1/tenants/${tid.value}/invitations`),
    ])
    users.value = usersRes.data
    invitations.value = invitationsRes.data
  } catch (err: unknown) {
    const axiosErr = err as { response?: { data?: { detail?: string } }; message?: string }
    toast.error(axiosErr.response?.data?.detail || axiosErr.message || 'Failed to load users')
  } finally {
    isLoading.value = false
  }
}

async function handleCreateUser() {
  if (!tid.value || !createEmail.value.trim() || !createUsername.value.trim() || !createPassword.value) return
  isCreating.value = true

  try {
    await apiClient.post(`/api/v1/tenants/${tid.value}/users`, {
      email: createEmail.value,
      username: createUsername.value,
      password: createPassword.value,
      full_name: createFullName.value.trim() || null,
      role: createRole.value,
    })
    showCreateModal.value = false
    createEmail.value = ''
    createUsername.value = ''
    createPassword.value = ''
    createFullName.value = ''
    createRole.value = 'analyst'
    toast.success('User created successfully')
    await fetchData()
  } catch (err: unknown) {
    const axiosErr = err as { response?: { data?: { detail?: string } }; message?: string }
    toast.error(axiosErr.response?.data?.detail || axiosErr.message || 'Failed to create user')
  } finally {
    isCreating.value = false
  }
}

async function handleInvite() {
  if (!tid.value || !inviteEmail.value.trim()) return
  isInviting.value = true

  try {
    await apiClient.post(`/api/v1/tenants/${tid.value}/invitations`, {
      email: inviteEmail.value,
      role: inviteRole.value,
    })
    showInviteModal.value = false
    inviteEmail.value = ''
    inviteRole.value = 'analyst'
    toast.success('Invitation sent')
    await fetchData()
  } catch (err: unknown) {
    const axiosErr = err as { response?: { data?: { detail?: string } }; message?: string }
    toast.error(axiosErr.response?.data?.detail || axiosErr.message || 'Failed to send invitation')
  } finally {
    isInviting.value = false
  }
}

async function handleUpdateRole(userId: number, role: string) {
  if (!tid.value) return

  try {
    await apiClient.patch(`/api/v1/tenants/${tid.value}/users/${userId}`, { role })
    editingUserId.value = null
    toast.success('Role updated')
    await fetchData()
  } catch (err: unknown) {
    const axiosErr = err as { response?: { data?: { detail?: string } }; message?: string }
    toast.error(axiosErr.response?.data?.detail || axiosErr.message || 'Failed to update role')
  }
}

async function handleToggleActive(user: TenantUser) {
  if (!tid.value) return

  try {
    await apiClient.patch(`/api/v1/tenants/${tid.value}/users/${user.id}`, {
      is_active: !user.membership_active,
    })
    toast.success(user.membership_active ? 'User deactivated' : 'User reactivated')
    await fetchData()
  } catch (err: unknown) {
    const axiosErr = err as { response?: { data?: { detail?: string } }; message?: string }
    toast.error(axiosErr.response?.data?.detail || axiosErr.message || 'Failed to update user')
  }
}

async function handleRevokeInvitation(id: number) {
  if (!tid.value) return

  try {
    await apiClient.delete(`/api/v1/tenants/${tid.value}/invitations/${id}`)
    toast.success('Invitation revoked')
    await fetchData()
  } catch (err: unknown) {
    const axiosErr = err as { response?: { data?: { detail?: string } }; message?: string }
    toast.error(axiosErr.response?.data?.detail || axiosErr.message || 'Failed to revoke invitation')
  }
}

function startEditRole(user: TenantUser) {
  editingUserId.value = user.id
  editingRole.value = user.role
}

function formatDate(dateStr: string | null): string {
  if (!dateStr) return 'Never'
  return new Date(dateStr).toLocaleDateString()
}

onMounted(fetchData)

watch(tid, () => {
  if (tid.value) {
    fetchData()
  }
})
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex justify-between items-center">
      <div>
        <h2 class="text-2xl font-bold text-gray-900 dark:text-dark-text-primary">User Management</h2>
        <p class="text-sm text-gray-500 dark:text-dark-text-tertiary mt-1">Manage team members and invitations</p>
      </div>
      <div class="flex gap-2">
        <button
          @click="showCreateModal = true"
          class="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 transition-colors text-sm font-medium"
        >
          Create User
        </button>
        <button
          @click="showInviteModal = true"
          class="px-4 py-2 border border-gray-300 dark:border-dark-border text-gray-700 dark:text-dark-text-secondary rounded-md hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary transition-colors text-sm font-medium"
        >
          Invite via Email
        </button>
      </div>
    </div>

    <!-- Which tenant are we managing? Superusers can switch inline. -->
    <div
      class="flex items-center gap-2 text-sm rounded-md border border-gray-200 dark:border-dark-border bg-gray-50 dark:bg-dark-bg-tertiary px-3 py-2"
    >
      <span class="text-gray-500 dark:text-dark-text-secondary"
        >Managing users for:</span
      >
      <span
        v-if="!isSuperuser"
        class="font-medium text-gray-900 dark:text-dark-text-primary"
      >
        {{ currentTenantName }}
      </span>
      <select
        v-else
        :value="tid"
        @change="switchTenant"
        aria-label="Select tenant to manage"
        class="font-medium text-gray-900 dark:text-dark-text-primary bg-transparent border border-gray-300 dark:border-dark-border rounded-md px-2 py-1 text-sm focus:outline-none focus:ring-2 focus:ring-primary-500 cursor-pointer"
      >
        <option
          v-for="t in tenantStore.tenants"
          :key="t.id"
          :value="t.id"
          class="bg-white dark:bg-dark-bg-primary"
        >
          {{ t.name }}
        </option>
      </select>
      <router-link
        v-if="isSuperuser"
        to="/admin/tenants"
        class="ml-auto text-primary-600 dark:text-primary-400 hover:underline"
      >
        All tenants
      </router-link>
    </div>

    <!-- Loading -->
    <div v-if="isLoading" role="status" class="flex items-center justify-center h-64">
      <div class="text-gray-600 dark:text-dark-text-secondary">Loading users...</div>
    </div>

    <template v-else>
      <!-- Users Table -->
      <div class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border overflow-hidden">
        <div class="px-6 py-4 border-b border-gray-200 dark:border-dark-border">
          <h3 class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary">Team Members ({{ users.length }})</h3>
        </div>

        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-gray-200 dark:divide-dark-border">
            <thead class="bg-gray-50 dark:bg-dark-bg-tertiary">
              <tr>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">User</th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">Role</th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">Status</th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">Last Login</th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody class="bg-white dark:bg-dark-bg-secondary divide-y divide-gray-200 dark:divide-dark-border">
              <tr v-for="u in users" :key="u.id" class="hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary">
                <td class="px-6 py-4">
                  <div class="text-sm font-medium text-gray-900 dark:text-dark-text-primary">{{ u.full_name || u.username }}</div>
                  <div class="text-xs text-gray-500 dark:text-dark-text-secondary">{{ u.email }}</div>
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                  <!-- Editing role -->
                  <template v-if="editingUserId === u.id">
                    <select
                      v-model="editingRole"
                      @change="handleUpdateRole(u.id, editingRole)"
                      class="text-sm border border-gray-300 dark:border-dark-border rounded px-2 py-1 dark:bg-dark-bg-tertiary dark:text-dark-text-primary"
                    >
                      <option v-for="r in roles" :key="r" :value="r">{{ r }}</option>
                    </select>
                  </template>
                  <template v-else>
                    <span
                      class="px-2.5 py-0.5 text-xs font-semibold rounded-full"
                      :class="getRoleBadgeClass(u.role)"
                    >
                      {{ u.role }}
                    </span>
                  </template>
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                  <span
                    class="px-2 py-0.5 text-xs font-semibold rounded-full"
                    :class="u.membership_active
                      ? 'bg-green-100 text-green-700 dark:bg-green-900/20 dark:text-green-400'
                      : 'bg-gray-100 text-gray-500 dark:bg-gray-700/30 dark:text-gray-400'"
                  >
                    {{ u.membership_active ? 'Active' : 'Inactive' }}
                  </span>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-dark-text-secondary">
                  {{ formatDate(u.last_login) }}
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm space-x-2">
                  <template v-if="u.role !== 'owner'">
                    <button
                      v-if="editingUserId !== u.id"
                      @click="startEditRole(u)"
                      class="text-primary-600 dark:text-primary-400 hover:text-primary-700 dark:hover:text-primary-300"
                    >
                      Edit Role
                    </button>
                    <button
                      @click="handleToggleActive(u)"
                      :class="u.membership_active
                        ? 'text-red-600 dark:text-red-400 hover:text-red-700 dark:hover:text-red-300'
                        : 'text-green-600 dark:text-green-400 hover:text-green-700 dark:hover:text-green-300'"
                    >
                      {{ u.membership_active ? 'Deactivate' : 'Reactivate' }}
                    </button>
                  </template>
                  <span v-else class="text-gray-400 dark:text-dark-text-tertiary text-xs italic">Owner</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Pending Invitations -->
      <div v-if="invitations.length > 0" class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border overflow-hidden">
        <div class="px-6 py-4 border-b border-gray-200 dark:border-dark-border">
          <h3 class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary">Pending Invitations ({{ invitations.length }})</h3>
        </div>

        <div class="divide-y divide-gray-200 dark:divide-dark-border">
          <div
            v-for="inv in invitations"
            :key="inv.id"
            class="px-6 py-3 flex items-center justify-between"
          >
            <div class="flex items-center gap-4">
              <span class="text-sm font-medium text-gray-900 dark:text-dark-text-primary">{{ inv.email }}</span>
              <span
                class="px-2.5 py-0.5 text-xs font-semibold rounded-full"
                :class="getRoleBadgeClass(inv.role)"
              >
                {{ inv.role }}
              </span>
              <span class="text-xs text-gray-500 dark:text-dark-text-secondary">
                Expires {{ formatDate(inv.expires_at) }}
              </span>
            </div>
            <button
              @click="handleRevokeInvitation(inv.id)"
              class="text-red-600 dark:text-red-400 hover:text-red-700 dark:hover:text-red-300 text-sm"
            >
              Revoke
            </button>
          </div>
        </div>
      </div>
    </template>

    <!-- Create User Modal -->
    <AppDialog :open="showCreateModal" title="Create User" @close="showCreateModal = false">
      <form @submit.prevent="handleCreateUser" class="space-y-4">
        <div>
          <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">Email</label>
          <input
            v-model="createEmail"
            type="email"
            required
            placeholder="user@example.com"
            class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
          />
        </div>

        <div>
          <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">Username</label>
          <input
            v-model="createUsername"
            type="text"
            required
            placeholder="jdoe"
            class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
          />
        </div>

        <div>
          <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">Full Name <span class="text-gray-400">(optional)</span></label>
          <input
            v-model="createFullName"
            type="text"
            placeholder="John Doe"
            class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
          />
        </div>

        <div>
          <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">Password</label>
          <input
            v-model="createPassword"
            type="password"
            required
            minlength="8"
            placeholder="Min. 8 characters"
            autocomplete="new-password"
            class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
          />
        </div>

        <div>
          <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">Role</label>
          <select
            v-model="createRole"
            class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
          >
            <option value="viewer">Viewer (read-only)</option>
            <option value="analyst">Analyst (read + write)</option>
            <option value="admin">Admin (full access)</option>
          </select>
        </div>

        <div class="flex justify-end gap-3 pt-2">
          <button
            type="button"
            @click="showCreateModal = false"
            class="px-4 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary transition-colors"
          >
            Cancel
          </button>
          <button
            type="submit"
            :disabled="isCreating || !createEmail.trim() || !createUsername.trim() || !createPassword"
            class="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {{ isCreating ? 'Creating...' : 'Create User' }}
          </button>
        </div>
      </form>
    </AppDialog>

    <!-- Invite Modal -->
    <AppDialog :open="showInviteModal" title="Invite User" description="Send an email invitation to join this tenant." @close="showInviteModal = false">
      <form @submit.prevent="handleInvite" class="space-y-4">
        <div>
          <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">Email Address</label>
          <input
            v-model="inviteEmail"
            type="email"
            required
            placeholder="colleague@example.com"
            class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
          />
        </div>

        <div>
          <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">Role</label>
          <select
            v-model="inviteRole"
            class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
          >
            <option value="viewer">Viewer (read-only)</option>
            <option value="analyst">Analyst (read + write)</option>
            <option value="admin">Admin (full access)</option>
          </select>
        </div>

        <div class="flex justify-end gap-3 pt-2">
          <button
            type="button"
            @click="showInviteModal = false"
            class="px-4 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary transition-colors"
          >
            Cancel
          </button>
          <button
            type="submit"
            :disabled="isInviting || !inviteEmail.trim()"
            class="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {{ isInviting ? 'Sending...' : 'Send Invitation' }}
          </button>
        </div>
      </form>
    </AppDialog>
  </div>
</template>
