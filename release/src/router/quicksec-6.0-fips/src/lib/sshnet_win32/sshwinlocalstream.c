/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Local stream implementation for Windows operating systems.
   Implemented using shared memory and process wide events and mutexes.

   Note: This uses a shared memory structure. For new local stream
   clients and old servers and vice versa to be mutually compatible,
   there is the implementation version information stored into the
   shared memory structure.

   The version information consists of 32 bits, of which the upper hald
   represents the major version, and the lower half the minor
   version. The minor version differences are designed to be
   compatible, the major versions changes cause incompatibilities.
*/

#include "sshincludes.h"
#include "sshlocalstream.h"
#include "ssheloop.h"
#include "sshtimeouts.h"
#include <aclapi.h>
#include <lmcons.h>
/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshStreamLocal"

#define SSH_LS_MUTEX_LOCK(m) WaitForSingleObject((m), INFINITE)
#define SSH_LS_MUTEX_UNLOCK(m) ReleaseMutex(m)

#define SSH_LS_MAX_NAME_LENGTH  512
#define SSH_LS_BUFFER_SIZE      4096
#define SSH_MAX_SID_SIZE        128

/* Ring buffer. */
struct SshLocalStreamRingBufferRec
{
  /* Flags. */
  unsigned int closed : 1;

  unsigned char data[SSH_LS_BUFFER_SIZE];
  size_t start;
  size_t end;
};

typedef struct SshLocalStreamRingBufferRec SshLocalStreamRingBufferStruct;
typedef struct SshLocalStreamRingBufferRec *SshLocalStreamRingBuffer;

/* A shared stream context.  This structure is allocated from shared
   memory and it is shared between both ends of the stream. */
struct SshLocalStreamSharedCtxRec
{
  /* Listener-wide unique ID for this stream. */
  SshUInt32 unique_id;

  /* Back-pointer to the local stream listener.  This points to the
     server's view of the listener.  It is not valid for client. */
  SshLocalListener listener;

  /* Ring buffers for both stream directions. */
  SshLocalStreamRingBufferStruct to_server;
  SshLocalStreamRingBufferStruct to_client;
};

typedef struct SshLocalStreamSharedCtxRec SshLocalStreamSharedCtxStruct;
typedef struct SshLocalStreamSharedCtxRec *SshLocalStreamSharedCtx;

/* Context for local stream.  This is allocated individually for both
   ends of the streams.  They share one shared context that is a
   shared memory block. */
struct SshLocalStreamCtxRec
{
  /* Shared stream context. */
  SshLocalStreamSharedCtx shared_ctx;

  /* Our handle to the shared stream context. */
  HANDLE shared_ctx_handle;

  /* Mutex protecting the shared stream context. */
  HANDLE shared_ctx_mutex_handle;

  /* Flags. */
  unsigned int server : 1;
  unsigned int read_blocked : 1;
  unsigned int write_blocked : 1;

  /* Streams.  This are in the normalized order; for client and
     server, these point to different ring buffers in the shared
     context. */
  SshLocalStreamRingBuffer read;
  SshLocalStreamRingBuffer write;

  /* Handles, used in signalling about status changes in the ring
     buffers. */
  HANDLE read_input_available;
  HANDLE read_can_output;
  HANDLE write_input_available;
  HANDLE write_can_output;

  /* Mutex which is locked as long as the client is alive. */
  HANDLE client_alive;

  /* The name of the mutex that server holds for a localstream. */
  char *server_mutex_name;

  /* User callback for the stream. */
  SshStreamCallback callback;
  void *callback_context;
};

typedef struct SshLocalStreamCtxRec SshLocalStreamCtxStruct;
typedef struct SshLocalStreamCtxRec *SshLocalStreamCtx;

#define SSH_WIN_LS_MAGIC_NUMBER 0xf00df00f
#define SSH_WIN_LS_CURRENT_VERSION 1
#define SSH_WIN_LS_VERSION_MAJOR(X) ((X & 0xffff0000) >> 16)
#define SSH_WIN_LS_VERSION_MINOR(X) (X & 0x0000ffff)

/* known versions of the local stream implementation are below. The updates to
   the local stream server functionality should preserve backward
   compatibility:


 - 0. First version. No version magic or version information, initial release.

 - 1. Contains Magic number and version number is zero. Added server
   user_name access_type to the structure

 - 2. Contains Magic and version number is 1. The real version
   numbering starts from here (defined major and minor number
   practises. A pointer to severSid is stored into shared memory
   struct.

*/

/* A local stream listener. This is allocated only for the server. */
struct SshLocalListenerRec
{
  /* The shared memory handle for this listener structure. */
  HANDLE listener_handle;

  /* The mutex that is hlod as long as the listener is alive */
  HANDLE server_alive;

  /*  The process id of the server. We try to check if the other
      end crahsed by trying to acquire it's mutex. If we succeed,
      then we know that the other end either was crashed or closed.
      However, if both server and client are in the same process,
      then we could be able to get the mutex, even if the other end
      is still alive. */
  SshUInt32 server_pid;

  /* Mutex protecting this local stream listener object.  This is used
     at the server end.  Clients have their own handles for the same
     mutex. */
  HANDLE mutex;

  /* The path of this local stream listener. */
  char *path;

  /* Number of references to this listener.  This includes the main
     listener object and active streams. */
  SshUInt32 refcount;

  /* Connection unique IDs. */
  SshUInt32 last_unique_id;
  SshUInt32 next_unique_id;

  /* Flags. */
  unsigned int destroyed : 1;

  /* Event that is signaled when a new client connects to this local
     listener. */
  HANDLE client_connect_event;

  /* Magic number which is used to ensure we are interfacing with the
     correct version of the local stream server (the client will check
     this magic. We must have a magic number because otherwise the old
     and new local stream implementations would not be compatible. The
     SSH Local Stream magic number is 0xf00df00f.  */
  SshUInt32 magic_number;

  /* For compatibility with old versions. The current version is 0 */
  SshUInt32 local_stream_version;

  /* The server user name needs to be available for other processes,
     so that the client processes can give perimissions to the shared
     objects so, that the server can open them */
  char server_user_name[UNLEN + 1];

  /* Local stream Access type */
  SshLocalStreamAccessType access_type;

  /* Space for the SID storage. This needs to be allocated inside this
     context, since the SID is used in the client as well. */
  unsigned char server_sid_space[SSH_MAX_SID_SIZE];

  /* User-supplied connection callback and context. */
  SshLocalCallback callback;
  void *callback_context;
};


/******************* Prototypes for static help functions *******************/

/* Destroy local listener `listener'.  The mutex protecting the
   listener must be locked when calling this function.  The function
   releases the mutex of the listener. */
static void do_destroy_listener(SshLocalListener listener);

/* The callback that is called by the event loop in a case, where
   the client handle becomes signalled. It should not happen, unless
   the client crashed */
static void local_stream_server_client_crashed(void *context);

/* The function that makes the stream to notify the application that
   the other end crashed. */
static void local_stream_peer_crashed(SshLocalStreamCtx stream_ctx);

/* Timeout callback that periodically checks whether the server is alive by
   opening the server-end mutex of the localstream.*/
void local_stream_check_server_alive(void *context);

#define myheapalloc(x) (HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, x))
#define myheapfree(x)  (HeapFree(GetProcessHeap(), 0, x))
#define INVALID_SECURITY_DESCRIPTOR NULL

Boolean ssh_get_current_user_sid(PSID pDestinationSid,
                                 DWORD nDestinationSidLength)
{
  HANDLE process_handle;
  HANDLE TokenHandle;
  unsigned char token_owner_space[SSH_MAX_SID_SIZE];
  DWORD token_owner_len = sizeof(token_owner_space);
  DWORD sid_len = 0;
  PTOKEN_OWNER token_owner = (PTOKEN_OWNER)token_owner_space;

  /* Get the process handle. The below call returns a pseudo
     handle, and can not fail.  the pseudo handle does not need
     to be freed. */
  process_handle = GetCurrentProcess();

  /* Open the process token to get the token handle */
  if (OpenProcessToken(process_handle, TOKEN_QUERY, &TokenHandle) == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("OpenProcess Token failed with %d",
                             GetLastError()));
      return FALSE;

    }

  /* Query the token owner SID, e.g the current user sid */
  if (GetTokenInformation(TokenHandle, TokenOwner,
                                   token_owner_space, token_owner_len,
                                   &token_owner_len) == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("GetTokenInformation failed.\n"));
      return FALSE;
    }

  /* Copy the sid to the destination buffer */
  if (CopySid(nDestinationSidLength, pDestinationSid, token_owner->Owner) == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("CopySid failed with %d", GetLastError()));
      return FALSE;
    }

  return TRUE;
}

static PSECURITY_DESCRIPTOR
ssh_winls_create_security_descriptor(SshLocalStreamAccessType access_type,
                                     const TCHAR *server_user_name,
                                     PSID server_sid,
                                     DWORD dwAccessMask)
{

  /*  SID variables. */
  LPVOID         pAdminSID       = NULL;
  DWORD          cbAdminSID      = 0;
  LPVOID         pUserSID       = NULL;
  DWORD          cbUserSID      = 0;
  LPVOID         pServerSID       = NULL;
  DWORD          cbServerSID      = 0;

  SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;

  /*  New SD variables. */
  PSECURITY_DESCRIPTOR  pnewSD = NULL;

  /*  ACL variables. */
  ACL_SIZE_INFORMATION AclInfo;

  /*  New ACL variables. */
  PACL           pNewACL        = NULL;
  DWORD          cbNewACL       = 0;

  /*  Assume function will fail. */
  BOOL           fResult        = FALSE;

  /* Domain variables */
  LPTSTR lpDomainBuffer[100];
  DWORD nDomainSize = sizeof(lpDomainBuffer);

  switch (access_type)
    {
      /* The most complicated case, fall through */
    case SSH_LOCAL_STREAM_ACCESS_ROOT:
      break;

      /* Return the default security descriptor. This was the old
         behaviour. */
    case SSH_LOCAL_STREAM_ACCESS_LOGON_SESSION:
      return NULL;

    case SSH_LOCAL_STREAM_ACCESS_ALL:
      pnewSD = myheapalloc(sizeof(SECURITY_DESCRIPTOR));
      /* Create a security descriptor with a NULL DACL. */
      if (!InitializeSecurityDescriptor(pnewSD,
                                        SECURITY_DESCRIPTOR_REVISION)) {
        SSH_DEBUG(SSH_D_FAIL, ("InitializeSecurityDescriptor() failed."
                               "Error %d\n", GetLastError()));
        return INVALID_SECURITY_DESCRIPTOR;
      }
      /* Allow all to connect!
      /* Set the NULL DACL to the new SD. */
      if (!SetSecurityDescriptorDacl(pnewSD, TRUE, NULL,
                                     FALSE)) {
        SSH_DEBUG(SSH_D_FAIL, ("SetSecurityDescriptorDacl() failed. "
                               "Error %d\n",
                               GetLastError()));
        return INVALID_SECURITY_DESCRIPTOR;
      }
      return pnewSD;
    }

  __try
    {
      SID_NAME_USE sid_type;

      /* should be enough for the user SID, 96 bits should suffice,
         but add few extra */
      pUserSID = myheapalloc(SSH_MAX_SID_SIZE);
      cbUserSID = SSH_MAX_SID_SIZE;

      /* Get current user SID */
      if (ssh_get_current_user_sid(pUserSID, cbUserSID) == FALSE)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Can not get the SID of the current user"));
          __leave;
        }
      if (server_sid == NULL && server_user_name != NULL)
        {
          pServerSID = myheapalloc(100);
          cbServerSID = 100;
          nDomainSize = sizeof(lpDomainBuffer);

          /* Look up the server SID */
          if (!LookupAccountName(NULL, (const char *)server_user_name,
                                 pServerSID,  &cbServerSID,
                                 (char *)lpDomainBuffer,
                                 &nDomainSize, &sid_type))
            {
              SSH_DEBUG(SSH_D_FAIL, ("Lookup account name failed, %d",
                                     GetLastError()));
              __leave;
            }
        }
      else
        {
          if (server_sid && IsValidSid(server_sid))
            {
              pServerSID = myheapalloc(SSH_MAX_SID_SIZE);
              cbServerSID = SSH_MAX_SID_SIZE;
              CopySid(cbServerSID, pServerSID, server_sid);
            }
        }


      /* Create a SID for the BUILTIN\Administrators group. */
      if (!AllocateAndInitializeSid(&SIDAuthNT, 2,
                                    SECURITY_BUILTIN_DOMAIN_RID,
                                    DOMAIN_ALIAS_RID_ADMINS,
                                    0, 0, 0, 0, 0, 0, &pAdminSID))
        {
          SSH_DEBUG(SSH_D_FAIL, ("AllocateAndInitalizeSid() failed."
                                 "Error %d\n", GetLastError()));
          __leave;
        }
      pnewSD = myheapalloc(sizeof(SECURITY_DESCRIPTOR));

      if (!InitializeSecurityDescriptor(pnewSD,
                                        SECURITY_DESCRIPTOR_REVISION)) {
        SSH_DEBUG(SSH_D_FAIL, ("InitializeSecurityDescriptor() failed."
                               "Error %d\n", GetLastError()));
        __leave;
      }

      /*   */
      /*  STEP 5: Get size information for DACL. */
      /*   */
      AclInfo.AceCount = 0; /*  Assume NULL DACL. */
      AclInfo.AclBytesFree = 0;
      AclInfo.AclBytesInUse = sizeof(ACL);

      cbNewACL = AclInfo.AclBytesInUse
        + sizeof(ACCESS_ALLOWED_ACE)  + GetLengthSid(pAdminSID)
        - sizeof(DWORD) +
        sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(pUserSID);

      if (pServerSID)
        cbNewACL += sizeof(ACCESS_ALLOWED_ACE) + GetLengthSid(pServerSID);

      /*   */
      /*  STEP 7: Allocate memory for new ACL. */
      /*   */
      pNewACL = (PACL) myheapalloc(cbNewACL);
      if (!pNewACL) {
        SSH_DEBUG(SSH_D_FAIL, ("HeapAlloc() failed. Error %d\n",
                               GetLastError()));
        __leave;
      }

      /*   */
      /*  STEP 8: Initialize the new ACL. */
      /*   */
      if (!InitializeAcl(pNewACL, cbNewACL, ACL_REVISION)) {
        SSH_DEBUG(SSH_D_FAIL, ("InitializeAcl() failed. Error %d\n",
                               GetLastError()));
        __leave;
      }
      /* Add Access for Administrators */
      if (!AddAccessAllowedAce(pNewACL, ACL_REVISION, dwAccessMask,
                               pAdminSID)) {
        SSH_DEBUG(SSH_D_FAIL, ("AddAccessAllowedAce() failed. Error %d\n",
                               GetLastError()));
        __leave;
      }

      /* Add Access for the current user */
      if (!AddAccessAllowedAce(pNewACL, ACL_REVISION, dwAccessMask,
                               pUserSID)) {
        SSH_DEBUG(SSH_D_FAIL, ("AddAccessAllowedAce() failed. Error %d\n",
                               GetLastError()));
        __leave;
      }

      /* Add Access for the local stream server process */
      if (pServerSID)
        {
          if (!AddAccessAllowedAce(pNewACL, ACL_REVISION, dwAccessMask,
                                   pServerSID))
            {
              SSH_DEBUG(SSH_D_FAIL, ("AddAccessAllowedAce() failed. "
                                     "Error %d\n", GetLastError()));
              __leave;
            }
        }
      /* Set the new DACL to the new SD. */
      if (!SetSecurityDescriptorDacl(pnewSD, TRUE, pNewACL,
                                     FALSE)) {
        SSH_DEBUG(SSH_D_FAIL, ("SetSecurityDescriptorDacl() failed. "
                               "Error %d\n",
                               GetLastError()));
        __leave;
      }

      fResult = TRUE;

    } __finally {

      /* Free allocated memory */
      if (pAdminSID)
        FreeSid(pAdminSID);

      if (pUserSID)
        myheapfree(pUserSID);

      if (pServerSID)
        myheapfree(pServerSID);
    }

  if (fResult == TRUE)
    return pnewSD;
  else
    {
      SSH_DEBUG(SSH_D_FAIL, ("Creation of security descriptor failed"));
      return INVALID_SECURITY_DESCRIPTOR;
    }
}

static void
ssh_winls_free_security_descriptor(PSECURITY_DESCRIPTOR psd)
{
  if (psd)
    {
      BOOL acl_present, default_dacl;
      PACL pacl = NULL;
      GetSecurityDescriptorDacl(psd, &acl_present, &pacl, &default_dacl);
      if (pacl && acl_present && !default_dacl)
        myheapfree(pacl);
      myheapfree(psd);
    }
}

/************************ Interprocess communication ************************/

/* Create a mutex for the name `name'.  The function returns an
   invalid handle if the mutex already exists or if the mutex creation
   fails.  Otherwise the function returns a handle to the new mutex
   that is locked.
*/

static HANDLE
create_mutex(const char *name, PSECURITY_DESCRIPTOR psd)
{
  SECURITY_ATTRIBUTES sa;
  HANDLE mutex;

  memset(&sa, 0, sizeof(sa));
  sa.bInheritHandle = TRUE;
  sa.nLength = sizeof(sa);
  sa.lpSecurityDescriptor = psd;

  mutex = CreateMutex(&sa, TRUE, name);
  if (mutex == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not create mutex `%s': %d",
                              name, GetLastError()));
      return NULL;
    }

  if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
      /* The mutex already exists. */
      SSH_DEBUG(SSH_D_FAIL, ("Mutex `%s' already exists", name));
      SSH_LS_MUTEX_UNLOCK(mutex);
      CloseHandle(mutex);
      return NULL;
    }

  /* We created the mutex. */
  return mutex;
}

/* Open an existing mutex `name' and lock it in exclusive mode.  The
   function returns a handle to the mutex of NULL if the operation
   fails. */
static HANDLE
open_mutex(const char *name)
{
  HANDLE mutex;

  mutex = CreateMutex(NULL, TRUE, name);
  if (mutex == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not open mutex `%s': %d",
                              name, GetLastError()));
      return NULL;
    }

  if (GetLastError() != ERROR_ALREADY_EXISTS)
    {
      /* We created the mutex. */
      SSH_DEBUG(SSH_D_FAIL, ("Mutex `%s' does not exist", name));
      SSH_LS_MUTEX_UNLOCK(mutex);
      CloseHandle(mutex);
      return NULL;
    }

  /* Success. */
  return mutex;
}

/* Create a Windows event for the name `name'.  The function returns a
   handle to the event or NULL if the operation fails. */
static HANDLE
create_event(const char *name, PSECURITY_DESCRIPTOR psd)
{
  SECURITY_ATTRIBUTES sa;

  memset(&sa, 0, sizeof(sa));
  sa.bInheritHandle = TRUE;
  sa.nLength = sizeof(sa);
  sa.lpSecurityDescriptor = psd;

  return CreateEvent(&sa, FALSE, FALSE, name);
}

/* Open a Window event `name'.  The function returns a handle to the
   event or NULL if the operation fails. */
static HANDLE
open_event(const char *name)
{
  return OpenEvent(EVENT_ALL_ACCESS, FALSE, name);
}

/* Signal event `event'. */
static void
signal_event(HANDLE event)
{
  SetEvent(event);
}

/* Signal event `name'. */
static void
signal_event_by_name(const char *name)
{
  HANDLE event;

  event = open_event(name);
  if (event == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not open event `%s'", name));
      return;
    }

  signal_event(event);
  CloseHandle(event);
}

/* Create shared memory block of size `size' for the name `name'.  The
   function returns TRUE if the operation was successful or FALSE
   otherwise.  If the operation is successful, a handle to the shared
   memory object is returned in `handle_return' and a pointer to its
   beginning in `ptr_return'.  The allocated memory is zeroed. */
static Boolean
create_shared_memory(const char *name, size_t size,
                     PSECURITY_DESCRIPTOR psd,
                     HANDLE *handle_return,
                     void **ptr_return)
{
  HANDLE filemap;
  SECURITY_ATTRIBUTES sa;

  memset(&sa, 0, sizeof(sa));
  sa.bInheritHandle = TRUE;
  sa.nLength = sizeof(sa);
  sa.lpSecurityDescriptor = psd;


  filemap = CreateFileMapping(INVALID_HANDLE_VALUE,
                              &sa,
                              PAGE_READWRITE,
                              0, (DWORD) size,
                              name);
  if (filemap == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not create file-mapping `%s': %d",
                              name, GetLastError()));
      return FALSE;
    }
  if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
      /* The file-mapping already exists. */
      SSH_DEBUG(SSH_D_FAIL, ("File-mapping `%s' already exists", name));
      CloseHandle(filemap);
      return FALSE;
    }

  /* We managed to create the file-mapping object.  Now, let's map it
     to this process' address space. */
  *ptr_return = MapViewOfFile(filemap, FILE_MAP_WRITE, 0, 0, (DWORD) size);
  if (*ptr_return == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not map file-mapping `%s' to process' "
                              "address space: %d", name, GetLastError()));
      CloseHandle(filemap);
      return FALSE;
    }

  /* Success. */
  memset(*ptr_return, 0, size);
  *handle_return = filemap;

  return TRUE;
}

/* Open shaed memory block of name `name'.  The function returns TRUE
   if the shared memory block could be opened or FALSE otherwise. */
static Boolean
open_shared_memory(const char *name, size_t size, HANDLE *handle_return,
                   void **ptr_return)
{
  HANDLE filemap;

  filemap = CreateFileMapping(INVALID_HANDLE_VALUE,
                              NULL,



                              PAGE_READWRITE,
                              0, (DWORD) size,
                              name);
  if (filemap == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not create file-mapping `%s': %d",
                              name, GetLastError()));
      return FALSE;
    }
  if (GetLastError() != ERROR_ALREADY_EXISTS)
    {
      /* The shared memory did not exist. */
      SSH_DEBUG(SSH_D_FAIL, ("File-mapping `%s' does not exist", name));
      CloseHandle(filemap);
      return FALSE;
    }

  /* It exists and we opened it.  Now, let's map it to this process'
     address space. */
  *ptr_return = MapViewOfFile(filemap, FILE_MAP_WRITE, 0, 0, (DWORD) size);
  if (*ptr_return == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not map file-mapping `%s' to process' "
                              "address space: %d", name, GetLastError()));
      CloseHandle(filemap);
      return FALSE;
    }

  /* Success. */
  *handle_return = filemap;

  return TRUE;
}

/* Close a shared memory object `handle', `ptr'. */
static void
close_shared_memory(HANDLE handle, void *ptr)
{
  (void) UnmapViewOfFile(ptr);
  CloseHandle(handle);
}


/************************* Stream method functions **************************/

static int
local_stream_read(void *context, unsigned char *buf, size_t size)
{
  SshLocalStreamCtx ctx = (SshLocalStreamCtx) context;
  int result = 0;

  SSH_ASSERT(size > 0);
  SSH_DEBUG(SSH_D_LOWSTART, ("Read: size=%lu", (unsigned long) size));

  SSH_LS_MUTEX_LOCK(ctx->shared_ctx_mutex_handle);

  if (ctx->read->start == ctx->read->end)
    {

      if (ctx->read->closed)
        {
          SSH_DEBUG(SSH_D_LOWOK, ("Closed"));
          result = 0;
        }
      else
        {
          /* No data in the buffer. */
          SSH_DEBUG(SSH_D_LOWOK, ("Would block"));
          result = -1;
        }
    }
  else
    {
      /* We have some data in the buffer. */
      while (ctx->read->start != ctx->read->end && size > 0)
        {
          size_t read;

          if (ctx->read->start > ctx->read->end)
            read = sizeof(ctx->read->data) - ctx->read->start;
          else
            read = ctx->read->end - ctx->read->start;

          if (read > size)
            read = size;

          memcpy(buf, ctx->read->data + ctx->read->start, read);

          size -= read;
          buf += read;

          result += (int)read;
          ctx->read->start += read;
          ctx->read->start %= sizeof(ctx->read->data);
        }

      SSH_DEBUG(SSH_D_LOWOK, ("Read %lu bytes", (unsigned long) result));

      /* Notify the other end that we consumed something from the
         stream. */
      signal_event(ctx->read_can_output);
    }

  SSH_LS_MUTEX_UNLOCK(ctx->shared_ctx_mutex_handle);

  if (result < 0)
    ctx->read_blocked = 1;

  return result;
}


static int
local_stream_write(void *context, const unsigned char *buf, size_t size)
{
  SshLocalStreamCtx ctx = (SshLocalStreamCtx) context;
  int result = 0;

  SSH_ASSERT(size > 0);
  SSH_DEBUG(SSH_D_LOWSTART, ("Write: size=%lu", (unsigned long) size));

  SSH_LS_MUTEX_LOCK(ctx->shared_ctx_mutex_handle);

  if (ctx->write->closed)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Closed"));
      result = 0;
    }
  else if ((ctx->write->end + 1) % sizeof(ctx->write->data)
           == ctx->write->start)
    {
      /* No space in the buffer. */
      SSH_DEBUG(SSH_D_LOWOK, ("Would block"));
      result = -1;
    }
  else
    {
      /* We can write something. */
      while (((ctx->write->end + 1) % sizeof(ctx->write->data)
              != ctx->write->start)
             && size > 0)
        {
          size_t write;

          if (ctx->write->end >= ctx->write->start)
            {
              write = sizeof(ctx->write->data) - ctx->write->end;
              if (ctx->write->start == 0)
                /* Must substract one because otherwise start and end
                   would be the same indicating an empty buffer. */
                write--;
            }
          else
            {
              write = ctx->write->start - ctx->write->end - 1;
            }

          if (write > size)
            write = size;

          memcpy(ctx->write->data + ctx->write->end, buf, write);

          size -= write;
          buf += write;

          result += (int)write;
          ctx->write->end += write;
          ctx->write->end %= sizeof(ctx->write->data);
        }

      SSH_DEBUG(SSH_D_LOWOK, ("Wrote %lu bytes", (unsigned long) result));

      /* Notify the other end that we produced some data to the
         stream. */
      signal_event(ctx->write_input_available);
    }

  SSH_LS_MUTEX_UNLOCK(ctx->shared_ctx_mutex_handle);

  if (result < 0)
    ctx->write_blocked = 1;

  return result;
}


static void
local_stream_output_eof(void *context)
{
  SshLocalStreamCtx ctx = (SshLocalStreamCtx) context;

  SSH_DEBUG(SSH_D_LOWSTART, ("Output EOF"));

  SSH_LS_MUTEX_LOCK(ctx->shared_ctx_mutex_handle);

  if (!ctx->write->closed)
    {
      ctx->write->closed = 1;

      /* Wake up the other end. */
      signal_event(ctx->write_input_available);
    }

  SSH_LS_MUTEX_UNLOCK(ctx->shared_ctx_mutex_handle);
}


static void
local_stream_set_callback(void *context, SshStreamCallback callback,
                          void *callback_context)
{
  SshLocalStreamCtx ctx = (SshLocalStreamCtx) context;

  SSH_DEBUG(SSH_D_LOWSTART, ("Set callback: callback=%p", callback));

  ctx->callback = callback;
  ctx->callback_context = callback_context;

  if (ctx->callback)
    {
      /* The callback is set.  This must result in a call to the
         callback.  Let's just assume that both operations have
         failed. */
      ctx->read_blocked = 1;
      ctx->write_blocked = 1;

      signal_event(ctx->read_input_available);
      signal_event(ctx->write_can_output);
    }
}


static void
local_stream_destroy(void *context)
{
  SshLocalStreamCtx ctx = (SshLocalStreamCtx) context;
  HANDLE mutex = ctx->shared_ctx_mutex_handle;

  SSH_DEBUG(SSH_D_LOWSTART, ("Destroy"));

  SSH_LS_MUTEX_LOCK(mutex);

  /* Mark the ring buffers closed and notify our remote peer. */
  if (!ctx->read->closed)
    {
      ctx->read->closed = 1;
      signal_event(ctx->read_can_output);
    }
  if (!ctx->write->closed)
    {
      ctx->write->closed = 1;
      signal_event(ctx->write_input_available);
    }

  /* On the server side, remove one reference from the global listener */
  if (ctx->server)
    {
      SSH_LS_MUTEX_LOCK(ctx->shared_ctx->listener->mutex);

      if (--ctx->shared_ctx->listener->refcount > 0)
        /* This was not the last reference. */
        SSH_LS_MUTEX_UNLOCK(ctx->shared_ctx->listener->mutex);
      else
        /* This was the last reference to the listener.  This will
           release the mutex. */
        do_destroy_listener(ctx->shared_ctx->listener);
    }


  /* Unmap our version of the shared stream context. */
  close_shared_memory(ctx->shared_ctx_handle, ctx->shared_ctx);

  /* Free our stream context. */

  ssh_event_loop_unregister_handle(ctx->read_input_available);
  ssh_event_loop_unregister_handle(ctx->write_can_output);

  ssh_cancel_timeouts(local_stream_check_server_alive, ctx);
  if (ctx->server_mutex_name)
    ssh_free(ctx->server_mutex_name);

  if (ctx->client_alive)
    ssh_event_loop_unregister_handle(ctx->client_alive);

  CloseHandle(ctx->read_input_available);
  CloseHandle(ctx->read_can_output);
  CloseHandle(ctx->write_input_available);
  CloseHandle(ctx->write_can_output);
  CloseHandle(ctx->client_alive);
  ssh_free(ctx);

  /* And finally, unlock the shared context's mutex and free our
     handle for it. */
  SSH_LS_MUTEX_UNLOCK(mutex);
  CloseHandle(mutex);
}


static const SshStreamMethodsStruct local_stream_methods =
{
  local_stream_read,
  local_stream_write,
  local_stream_output_eof,
  local_stream_set_callback,
  local_stream_destroy,
};

/* An event callback function that is called when the other end
   indicates that there is new input in the local stream `context'. */
static void
local_stream_input_available(void *context)
{
  SshLocalStreamCtx ctx = (SshLocalStreamCtx) context;

  SSH_DEBUG(SSH_D_LOWSTART, ("Input available"));

  if (ctx->callback && ctx->read_blocked)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Calling user callback"));
      ctx->read_blocked = 0;
      (*ctx->callback)(SSH_STREAM_INPUT_AVAILABLE, ctx->callback_context);
    }
  else
    {
      if (ctx->callback == NULL)
        SSH_DEBUG(SSH_D_LOWOK, ("Callback unset"));
      else
        SSH_DEBUG(SSH_D_LOWOK, ("User is not blocked"));
    }
}

/* An event callback function that is called when the other end
   indicates that there is space for new data in the local stream
   `context'. */
static void
local_stream_can_output(void *context)
{
  SshLocalStreamCtx ctx = (SshLocalStreamCtx) context;

  SSH_DEBUG(SSH_D_LOWSTART, ("Can output"));

  if (ctx->callback && ctx->write_blocked)
    {
      SSH_DEBUG(SSH_D_LOWOK, ("Calling user callback"));
      ctx->write_blocked = 0;
      (*ctx->callback)(SSH_STREAM_CAN_OUTPUT, ctx->callback_context);
    }
  else
    {
      if (ctx->callback == NULL)
        SSH_DEBUG(SSH_D_LOWOK, ("Callback unset"));
      else
        SSH_DEBUG(SSH_D_LOWOK, ("User is not blocked"));
    }
}


/******************************* Server side ********************************/

/* A callback function that is called when a new client connection is
   made to the local stream listener `context'. */
static void
client_connect_cb(void *context)
{
  SshLocalListener listener = (SshLocalListener) context;

  SSH_LS_MUTEX_LOCK(listener->mutex);

  SSH_DEBUG(SSH_D_NICETOKNOW, ("New connection for listener `%s'",
                               listener->path));
  SSH_DEBUG(SSH_D_LOWOK, ("refcount=%lu", (unsigned long) listener->refcount));

  SSH_ASSERT(listener->refcount > 0);

  /* Process all new connections. */
  for (;
       listener->last_unique_id < listener->next_unique_id;
       listener->last_unique_id++)
    {
      char name[SSH_LS_MAX_NAME_LENGTH];
      SshUInt32 unique_id = listener->last_unique_id;
      HANDLE shared_ctx_mutex_handle = NULL;
      HANDLE shared_ctx_handle = NULL;
      SshLocalStreamSharedCtx shared_ctx = NULL;
      SshLocalStreamCtx stream_ctx = NULL;
      SshStream stream = NULL;

      /* Lock the shared context. */

      ssh_snprintf(name, sizeof(name), "SSH_LS_MUTEX(%s,STREAM%lu)",
                   listener->path, (unsigned long) unique_id);

      shared_ctx_mutex_handle = open_mutex(name);
      if (shared_ctx_mutex_handle == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Could not open mutex `%s'", name));
          continue;
        }

      /* We have a lock for the stream.  Let's open its shared memory. */
      ssh_snprintf(name, sizeof(name), "SSH_LS_MEMORY(%s,STREAM%lu)",
                   listener->path, (unsigned long) unique_id);

      if (!open_shared_memory(name, sizeof(*shared_ctx), &shared_ctx_handle,
                              &shared_ctx))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Could not open shared memory `%s'", name));
          SSH_LS_MUTEX_UNLOCK(shared_ctx_mutex_handle);
          CloseHandle(shared_ctx_mutex_handle);
          continue;
        }

      if (shared_ctx->listener != NULL)
        {




          SSH_DEBUG(SSH_D_FAIL, ("shared memory invalid `%s'", name));
          SSH_LS_MUTEX_UNLOCK(shared_ctx_mutex_handle);
          CloseHandle(shared_ctx_mutex_handle);
          CloseHandle(shared_ctx_handle);
          continue;
        }

      /* Set the global listener to the shared context. */
      SSH_ASSERT(shared_ctx->listener == NULL);
      shared_ctx->listener = listener;

      /* Allocate our copy of the stream. */

      stream_ctx = ssh_calloc(1, sizeof(*stream_ctx));
      if (stream_ctx == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Could not allocate server's stream context"));
        error:

          if (stream_ctx)
            {
              if (stream_ctx->read_can_output)
                CloseHandle(stream_ctx->read_can_output);
              if (stream_ctx->read_input_available)
                CloseHandle(stream_ctx->read_input_available);
              if (stream_ctx->write_can_output)
                CloseHandle(stream_ctx->write_can_output);
              if (stream_ctx->write_input_available)
                CloseHandle(stream_ctx->write_input_available);
              ssh_free(stream_ctx);
            }

          if (shared_ctx)
            {
              /* Destroy the stream by hand. */
              if (!shared_ctx->to_server.closed)
                {
                  shared_ctx->to_server.closed = 1;

                  ssh_snprintf(name, sizeof(name),
                               "SSH_LS_EVENT(%s,STREAM%lu,"
                               "TO_SERVER,CAN_OUTPUT)",
                               listener->path, (unsigned long) unique_id);
                  signal_event_by_name(name);
                }
              if (!shared_ctx->to_client.closed)
                {
                  shared_ctx->to_client.closed = 1;

                  ssh_snprintf(name, sizeof(name),
                               "SSH_LS_EVENT(%s,STREAM%lu,"
                               "TO_CLIENT,INPUT_AVAILABLE)",
                               listener->path, (unsigned long) unique_id);
                  signal_event_by_name(name);
                }
            }

          /* Unmap and unlock the shared stream context. */
          close_shared_memory(shared_ctx_handle, shared_ctx);
          SSH_LS_MUTEX_UNLOCK(shared_ctx_mutex_handle);
          CloseHandle(shared_ctx_mutex_handle);

          /* And remove one reference from the global listener. */
          SSH_ASSERT(listener->refcount > 0);
          listener->refcount--;

          continue;
        }

      stream_ctx->shared_ctx = shared_ctx;
      stream_ctx->shared_ctx_handle = shared_ctx_handle;
      stream_ctx->shared_ctx_mutex_handle = shared_ctx_mutex_handle;

      stream_ctx->server = 1;

      stream_ctx->read = &shared_ctx->to_server;
      stream_ctx->write = &shared_ctx->to_client;

      /* Open synchronization events for ring buffers. */

      ssh_snprintf(name, sizeof(name),
                   "SSH_LS_EVENT(%s,STREAM%lu,TO_SERVER,INPUT_AVAILABLE)",
                   listener->path, (unsigned long) unique_id);
      stream_ctx->read_input_available = open_event(name);

      ssh_snprintf(name, sizeof(name),
                   "SSH_LS_EVENT(%s,STREAM%lu,TO_SERVER,CAN_OUTPUT)",
                   listener->path, (unsigned long) unique_id);
      stream_ctx->read_can_output = open_event(name);

      ssh_snprintf(name, sizeof(name),
                   "SSH_LS_EVENT(%s,STREAM%lu,TO_CLIENT,INPUT_AVAILABLE)",
                   listener->path, (unsigned long) unique_id);
      stream_ctx->write_input_available = open_event(name);

      ssh_snprintf(name, sizeof(name),
                   "SSH_LS_EVENT(%s,STREAM%lu,TO_CLIENT,CAN_OUTPUT)",
                   listener->path, (unsigned long) unique_id);
      stream_ctx->write_can_output = open_event(name);

      ssh_snprintf(name, sizeof(name),
                   "SSH_LS_MUTEX(%s,STREAM%luALIVE)",
                   listener->path, (unsigned long) unique_id);

      stream_ctx->client_alive = open_mutex(name);
      if (stream_ctx->client_alive == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Could not open the clients alive mutex, "
                     "it must have been crashed"));
          goto error;
        }


      if (stream_ctx->read_input_available == NULL
          || stream_ctx->read_can_output == NULL
          || stream_ctx->write_input_available == NULL
          || stream_ctx->write_can_output == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL,
                    ("Could not create ring buffer synchronization events"));
          goto error;
        }

      /* Create the user stream. */
      stream = ssh_stream_create(&local_stream_methods, stream_ctx);
      if (stream == NULL)
        {
          SSH_DEBUG(SSH_D_FAIL, ("Could not create user stream"));
          goto error;
        }

        /* If we can get the mutex right of way, we are in the same
         thread as the client. If so, do nothing */
      if (WaitForSingleObject(stream_ctx->client_alive, 0) == WAIT_TIMEOUT)
        {
          /* We are in different thread. Wait for client crashes */
          ssh_event_loop_register_handle(stream_ctx->client_alive, FALSE,
                                         local_stream_server_client_crashed,
                                         stream_ctx);
        }

      /* Start receiving events from our remote peer. */
      ssh_event_loop_register_handle(stream_ctx->read_input_available, FALSE,
                                     local_stream_input_available, stream_ctx);
      ssh_event_loop_register_handle(stream_ctx->write_can_output, FALSE,
                                     local_stream_can_output, stream_ctx);

      /* The stream is now ready and we can relase the shared context
         lock. */
      SSH_LS_MUTEX_UNLOCK(shared_ctx_mutex_handle);

      /* Notify our user about this new connection.  But release mutex
         in between.  We must use reference counts to protect the
         listener structure. */
      listener->refcount++;
      SSH_LS_MUTEX_UNLOCK(listener->mutex);

      (*listener->callback)(stream, listener->callback_context);

      SSH_LS_MUTEX_LOCK(listener->mutex);

      if (--listener->refcount > 0)
        /* The listener context did not go away.  Process the next new
           connection. */
        continue;

      /* The listener was destroyed from the connection callback. */
      do_destroy_listener(listener);
      return;
    }

  /* All new connections processed. */
  SSH_LS_MUTEX_UNLOCK(listener->mutex);
}




SshLocalListener
ssh_local_make_listener(const unsigned char *path,
                        SshLocalStreamParams params,
                        SshLocalCallback callback,
                        void *context)
{
  HANDLE mutex;
  HANDLE listener_handle;
  char name[SSH_LS_MAX_NAME_LENGTH];
  SshLocalListener listener;
  PSECURITY_DESCRIPTOR psd;
  TCHAR server_user_name[UNLEN + 1];
  DWORD server_user_name_len = UNLEN;
  SshLocalStreamAccessType access_type;

  if (params != NULL)
    access_type = params->access;
  else
    access_type = SSH_LOCAL_STREAM_ACCESS_ROOT;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Creating local stream listener with "
                               "path %s",
                               path));

  psd = ssh_winls_create_security_descriptor(access_type,
                                             NULL, NULL, GENERIC_ALL);
  /* Create a mutex for the listener.  The operation fails if the
     mutex already exits - there is already a listener with the name
     `path' or the mutex creation failed because we run out of
     resources. */

  ssh_snprintf(name, sizeof(name), "SSH_LS_MUTEX(%s)", path);
  mutex = create_mutex(name, psd);
  if (mutex == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Could not create mutex for the local stream listener `%s'",
                 path));
      ssh_winls_free_security_descriptor(psd);
      return NULL;
    }

  /* Mutex created and locked.  We are creating this local stream
     listener.  Let's allocate and initialize the listener object. */

  ssh_snprintf(name, sizeof(name), "SSH_LS_MEMORY(%s,LISTENER)", path);
  if (!create_shared_memory(name, sizeof(*listener), psd, &listener_handle,
                            &listener))
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Could not create shared memory for the listener `%s'",
                 path));
      ssh_winls_free_security_descriptor(psd);
      SSH_LS_MUTEX_UNLOCK(mutex);
      CloseHandle(mutex);
      return NULL;
    }
  listener->server_pid = GetCurrentProcessId();
  listener->listener_handle = listener_handle;
  listener->mutex = mutex;
  listener->magic_number = SSH_WIN_LS_MAGIC_NUMBER;
  listener->local_stream_version = SSH_WIN_LS_CURRENT_VERSION;
  listener->access_type = access_type;

  GetUserName(server_user_name, &server_user_name_len);
  memcpy(listener->server_user_name, server_user_name, UNLEN);

  if (ssh_get_current_user_sid(listener->server_sid_space,
                               SSH_MAX_SID_SIZE) == FALSE)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Failed to get the current user SID"));
      goto error;
    }

  listener->path = ssh_strdup(path);
  if (listener->path == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not duplicate listener's path"));
      goto error;
    }

  /* Initially, we have just one reference. */
  listener->refcount = 1;

  listener->callback = callback;
  listener->callback_context = context;


  /* Create a mutex which clients use to detect if the listener crashed */
  ssh_snprintf(name, sizeof(name), "SSH_LS_MUTEX(%s,SERVER_ALIVE)", path);
  listener->server_alive = create_mutex(name, psd);
  if (listener->server_alive == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Could not create server alive mutex `%s'",
                 path));
      goto error;
    }
  SSH_LS_MUTEX_LOCK(listener->server_alive);

  /* Create an event for signaling the server about client
     connection. */

  ssh_snprintf(name, sizeof(name), "SSH_LS_EVENT(%s,CLIENT_CONNECT)", path);
  listener->client_connect_event = create_event(name, psd);
  if (listener->client_connect_event == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Could not create client connect event for listener `%s'",
                 path));
      goto error;
    }
  /* Start monitoring the client connects. */
  ssh_event_loop_register_handle(listener->client_connect_event, FALSE,
                                 client_connect_cb, listener);

  /* All done. */
  SSH_DEBUG(SSH_D_LOWOK, ("Local stream listener `%s' created", path));
  SSH_LS_MUTEX_UNLOCK(listener->mutex);
  ssh_winls_free_security_descriptor(psd);
  return listener;

  /* Error handling. */

 error:
  ssh_winls_free_security_descriptor(psd);
  if (listener)
    {
      if (listener->mutex)
        {
          SSH_LS_MUTEX_UNLOCK(listener->mutex);
          CloseHandle(listener->mutex);
        }

      ssh_free(listener->path);

      if (listener->client_connect_event)
        CloseHandle(listener->client_connect_event);
      if (listener->server_alive)
        CloseHandle(listener->server_alive);
      /* And finally, free the listener structure. */
      SSH_ASSERT(listener->listener_handle != NULL);
      close_shared_memory(listener->listener_handle, listener);
    }

  return NULL;
}

/* The function that makes the stream to notify the application that
   the other end crashed. */
static void local_stream_peer_crashed(SshLocalStreamCtx ctx)
{
  ctx->read->closed = 1;
  ctx->write->closed = 1;

  if (ctx->read_blocked)
    signal_event(ctx->read_input_available);

  if (ctx->write_blocked)
    signal_event(ctx->write_can_output);
}


static void local_stream_server_client_crashed(void *context)
{
  SshLocalStreamCtx stream_ctx = context;
  SSH_DEBUG(SSH_D_FAIL, ("The client probably crashed"));
  local_stream_peer_crashed(stream_ctx);

  ssh_event_loop_unregister_handle(stream_ctx->client_alive);
  CloseHandle(stream_ctx->client_alive);
  stream_ctx->client_alive = NULL;
}


static void
do_destroy_listener(SshLocalListener listener)
{
  HANDLE mutex = listener->mutex;

  SSH_ASSERT(listener->destroyed);

  ssh_free(listener->path);

  ssh_event_loop_unregister_handle(listener->client_connect_event);
  CloseHandle(listener->client_connect_event);

  /* Unlock the alive mutex. Now the existing clients now that
     we went down. */
  SSH_LS_MUTEX_UNLOCK(listener->server_alive);
  CloseHandle(listener->server_alive);

  /* Release the shared memory object presenting this local stream
     listener. */
  close_shared_memory(listener->listener_handle, listener);

  /* Unlock and destroy the mutex.  This completes the destroy
     operation. */
  SSH_LS_MUTEX_UNLOCK(mutex);
  CloseHandle(mutex);
}


void
ssh_local_destroy_listener(SshLocalListener listener)
{
  SSH_LS_MUTEX_LOCK(listener->mutex);

  listener->destroyed = 1;

  if (--listener->refcount > 0)
    {
      /* This was not the last reference. */
      SSH_LS_MUTEX_UNLOCK(listener->mutex);
      return;
    }

  /* This is the last reference. */
  do_destroy_listener(listener);
}


/******************************* Client side ********************************/

/* This is called only if, the server handle becomes signaled. */
void local_stream_client_server_crashed(void *context)
{
  SshLocalStreamCtx stream_ctx = context;

  SSH_DEBUG(SSH_D_FAIL, ("The server probably crashed"));
  local_stream_peer_crashed(stream_ctx);
}

void local_stream_check_server_alive(void *context)
{
  SshLocalStreamCtx stream_ctx = context;
  HANDLE server_mutex;

  server_mutex = open_mutex(stream_ctx->server_mutex_name);
  if (server_mutex == NULL)
  {
    /* mutex could not be opened, server has crashed */
    local_stream_client_server_crashed(context);
    return;
  }
  SSH_DEBUG(SSH_D_NICETOKNOW, ("server is still alive"));
  CloseHandle(server_mutex);

  /* come here again */
  ssh_xregister_timeout(2, 0, local_stream_check_server_alive, context);
}

SshOperationHandle
ssh_local_connect(const unsigned char *path,
                  SshLocalCallback callback,
                  void *context)
{
  char name[SSH_LS_MAX_NAME_LENGTH];
  HANDLE mutex = NULL;
  HANDLE listener_handle = NULL;
  SshLocalListener listener = NULL;
  HANDLE new_connection_event_handle = NULL;
  SshUInt32 unique_id;
  SshLocalStreamSharedCtx shared_ctx = NULL;
  HANDLE shared_ctx_handle = NULL;
  HANDLE shared_ctx_mutex_handle = NULL;
  SshLocalStreamCtx stream_ctx = NULL;
  SshStream stream = NULL;
  PSECURITY_DESCRIPTOR psd = NULL;

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Connecting to the local stream listener `%s'",
                               path));

  /* Open the mutex of the listener.  If the operation fails it
     probably means that there is no such listener.  If it is
     successful, we have the listener handle exclusively locked. */

  ssh_snprintf(name, sizeof(name), "SSH_LS_MUTEX(%s)", path);
  mutex = open_mutex(name);
  if (mutex == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Could not open mutex of the local stream listener `%s'",
                 path));
      goto error;
    }

  /* Open the listener's shared memory. */

  ssh_snprintf(name, sizeof(name), "SSH_LS_MEMORY(%s,LISTENER)", path);
  if (!open_shared_memory(name, sizeof(*listener), &listener_handle,
                          &listener))
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Could not open shared memory of the local stream "
                 "listener `%s'", path));
      goto error;
    }

  if (listener->magic_number == SSH_WIN_LS_MAGIC_NUMBER)
    {
      PSID server_sid = NULL;
      if (SSH_WIN_LS_VERSION_MAJOR(listener->local_stream_version) !=
          SSH_WIN_LS_VERSION_MAJOR(SSH_WIN_LS_CURRENT_VERSION))
        {
          SSH_DEBUG(SSH_D_FAIL, ("Version mismatch"));
          goto error;
        }
      if (listener->local_stream_version > 0)
        {
          /* There is the server sid stored into the listener */
          server_sid = (PSID)listener->server_sid_space;
        }

      /* The listener magic number matched, it is possible that we
         have the server processes user name in the context, so that
         we can specify the appropriate permissions */
      psd = ssh_winls_create_security_descriptor(listener->access_type,
                                                 listener->server_user_name,
                                                 server_sid,
                                                 GENERIC_ALL);
    }
  else
    {
      /* The local stream listener is probably of the older version,
         which does not care about security descriptors, thus we
         should probably just use the default permissions as well */
      psd = NULL;
    }

  /* Open the `notify-new-connection' event. */
  ssh_snprintf(name, sizeof(name), "SSH_LS_EVENT(%s,CLIENT_CONNECT)", path);
  new_connection_event_handle = open_event(name);
  if (new_connection_event_handle == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not open `notify-new-connection' event"));
      goto error;
    }

  /* Now we have the listener object.  Let's create a shared stream
     context. */

  unique_id = listener->next_unique_id++;

  ssh_snprintf(name, sizeof(name), "SSH_LS_MEMORY(%s,STREAM%lu)",
               path, (unsigned long) unique_id);
  if (!create_shared_memory(name, sizeof(*shared_ctx), psd,
                            &shared_ctx_handle,
                            &shared_ctx))
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Could not create shared memory for a local stream "
                 "to listener `%s'", path));
      goto error;
    }

  ssh_snprintf(name, sizeof(name), "SSH_LS_MUTEX(%s,STREAM%lu)",
               path, (unsigned long) unique_id);

  shared_ctx_mutex_handle = create_mutex(name, psd);
  if (shared_ctx_mutex_handle == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not create mutex"));
      goto error;
    }

  shared_ctx->unique_id = unique_id;

  /* Alloc and init user stream context. */

  stream_ctx = ssh_calloc(1, sizeof(*stream_ctx));
  if (stream_ctx == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not allocate client's stream context"));
      goto error;
    }

  if (GetCurrentProcessId() != listener->server_pid)
    {
    /* We are in a different process. Try to open the mutex that server has
       created. The existence of the mutex indicates that the localstream is
       up and running.
       Note that we cannot register the mutex into the event loop to get a
       signal from server crash. This solution didn't work on Win9x in the
       case where the client process had more than one localstreams to the
       same listener. Instead of registering the mutex into event loop, we try
       to open it periodically from a timeout. When the open fails, we know
       that server has crashed. */
       HANDLE server_mutex;
       ssh_snprintf(name, sizeof(name), "SSH_LS_MUTEX(%s,SERVER_ALIVE)", path);
       server_mutex = open_mutex(name);
       if (server_mutex == NULL)
         {
            SSH_DEBUG(SSH_D_FAIL,
                      ("Could not open the server mutex %s", path));
            goto error;
         }
       CloseHandle(server_mutex);

       /* check mutex again in timeout */
       stream_ctx->server_mutex_name = ssh_xstrdup(name);
       if (stream_ctx->server_mutex_name == NULL)
         goto error;
       ssh_xregister_timeout(1, 0, local_stream_check_server_alive,
                             stream_ctx);
    }

  stream_ctx->shared_ctx = shared_ctx;
  stream_ctx->shared_ctx_handle = shared_ctx_handle;
  stream_ctx->shared_ctx_mutex_handle = shared_ctx_mutex_handle;

  stream_ctx->read = &shared_ctx->to_client;
  stream_ctx->write = &shared_ctx->to_server;

  /* Create synchronization variables for ring buffers. */

  ssh_snprintf(name, sizeof(name),
               "SSH_LS_EVENT(%s,STREAM%lu,TO_CLIENT,INPUT_AVAILABLE)",
               path, (unsigned long) unique_id);
  stream_ctx->read_input_available = create_event(name, psd);

  ssh_snprintf(name, sizeof(name),
               "SSH_LS_EVENT(%s,STREAM%lu,TO_CLIENT,CAN_OUTPUT)",
               path, (unsigned long) unique_id);
  stream_ctx->read_can_output = create_event(name, psd);

  ssh_snprintf(name, sizeof(name),
               "SSH_LS_EVENT(%s,STREAM%lu,TO_SERVER,INPUT_AVAILABLE)",
               path, (unsigned long) unique_id);
  stream_ctx->write_input_available = create_event(name, psd);

  ssh_snprintf(name, sizeof(name),
               "SSH_LS_EVENT(%s,STREAM%lu,TO_SERVER,CAN_OUTPUT)",
               path, (unsigned long) unique_id);
  stream_ctx->write_can_output = create_event(name, psd);

  ssh_snprintf(name, sizeof(name),
               "SSH_LS_MUTEX(%s,STREAM%luALIVE)",
               path, (unsigned long) unique_id);
  stream_ctx->client_alive = create_mutex(name, psd);


  if (stream_ctx->read_input_available == NULL
      || stream_ctx->read_can_output == NULL
      || stream_ctx->write_input_available == NULL
      || stream_ctx->write_can_output == NULL
      || stream_ctx->client_alive == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL,
                ("Could not create ring buffer synchronization events"));
      goto error;
    }
  SSH_LS_MUTEX_LOCK(stream_ctx->client_alive);

  /* Create the user stream. */
  stream = ssh_stream_create(&local_stream_methods, stream_ctx);
  if (stream == NULL)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Could not create user stream"));
      goto error;
    }

  /* Start receiving events from our remote peer. */

  ssh_event_loop_register_handle(stream_ctx->read_input_available, FALSE,
                                 local_stream_input_available, stream_ctx);
  ssh_event_loop_register_handle(stream_ctx->write_can_output, FALSE,
                                 local_stream_can_output, stream_ctx);

  /* We created one new connection so we must add one reference to the
     global listener. */
  listener->refcount++;

  /* Free the global listener mutex and shared memory object.  We do
     not need them anymore. */
  SSH_LS_MUTEX_UNLOCK(mutex);
  CloseHandle(mutex);
  close_shared_memory(listener_handle, listener);

  /* Notify both ends of the stream.  Unlock the mutex of the shared
     stream context first to avoid deadlocks. */

  SSH_LS_MUTEX_UNLOCK(shared_ctx_mutex_handle);

  signal_event(new_connection_event_handle);
  CloseHandle(new_connection_event_handle);

  (*callback)(stream, context);

  ssh_winls_free_security_descriptor(psd);

  /* All done. */
  return NULL;

  /* Error handling. */

 error:
  ssh_winls_free_security_descriptor(psd);
  if (stream_ctx)
    {
      if (stream_ctx->read_input_available)
        CloseHandle(stream_ctx->read_input_available);
      if (stream_ctx->read_can_output)
        CloseHandle(stream_ctx->read_can_output);
      if (stream_ctx->write_input_available)
        CloseHandle(stream_ctx->write_input_available);
      if (stream_ctx->write_can_output)
        CloseHandle(stream_ctx->write_can_output);
      if (stream_ctx->client_alive)
        CloseHandle(stream_ctx->client_alive);

      ssh_free(stream_ctx);
    }

  if (shared_ctx_mutex_handle)
    {
      SSH_LS_MUTEX_UNLOCK(shared_ctx_mutex_handle);
      CloseHandle(shared_ctx_mutex_handle);
    }

  if (shared_ctx)
    close_shared_memory(shared_ctx_handle, shared_ctx);

  if (listener)
    close_shared_memory(listener_handle, listener);

  if (new_connection_event_handle)
    CloseHandle(new_connection_event_handle);

  if (mutex)
    {
      SSH_LS_MUTEX_UNLOCK(mutex);
      CloseHandle(mutex);
    }

  (*callback)(NULL, context);
  return NULL;
}

