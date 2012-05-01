#include "uuid.h"
#include "erl_nif.h"
#include <string.h>

// Prototypes
#define NIF(name) ERL_NIF_TERM name(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])

NIF(ossp_uuid_nif_make);
NIF(ossp_uuid_nif_import);

int ossp_uuid_mode(char *version, unsigned int *mode);
int ossp_uuid_fmt(char *format, uuid_fmt_t *fmt, size_t *len);

static ErlNifFunc nif_funcs[] =
{
    {"make", 2, ossp_uuid_nif_make},
    {"make", 4, ossp_uuid_nif_make},
    {"import", 2, ossp_uuid_nif_import}
};

int make_uuid_ns(uuid_t * uuid, unsigned int mode, ErlNifEnv *env, const ERL_NIF_TERM argv[]) {
  unsigned int length;
  char * ns = NULL;
  char * name = NULL;
  uuid_t *uuid_ns = NULL;
  int ret = 0;

  if (!enif_get_list_length(env, argv[2], &length)) {
    return 0;
  }
  
  ns = malloc(length + 1);
  if (ns == NULL) {
    goto ERR;
  }
  
  if (enif_get_string(env, argv[2], ns, length+1, ERL_NIF_LATIN1) < 1) {
    goto ERR;
  }
  
  if (!enif_get_list_length(env, argv[3], &length)) {
    goto ERR;
  }

  name = malloc(length + 1);
  if (name == NULL) {
    goto ERR;
  }
  
  if (enif_get_string(env, argv[3], name, length+1, ERL_NIF_LATIN1) < 1) {
    free(ns); free(name);
    return enif_make_badarg(env);
  }

  if (uuid_create(&uuid_ns) != UUID_RC_OK) {
    goto ERR;
  }
  if (uuid_load(uuid_ns, ns) != UUID_RC_OK) {
    goto ERR;
  }

  if (uuid_make(uuid, mode, uuid_ns, name) != UUID_RC_OK) {
    goto ERR;
  }

  ret = 1;

ERR:
  if (uuid_ns) {
    (void)uuid_destroy(uuid_ns);
  }

  if (ns) {
    free(ns);
  }

  if (name) {
    free(name);
  }

  return ret;
}

int ossp_uuid_mode(char *version, unsigned int *mode)
{
  if (!strcmp(version,"v1")) {
     *mode = UUID_MAKE_V1;
  } else if (!strcmp(version,"v3")) {
     *mode = UUID_MAKE_V3;
  } else if (!strcmp(version,"v4")) {
     *mode = UUID_MAKE_V4;
  } else if (!strcmp(version,"v5")) {
     *mode = UUID_MAKE_V5;
  } else {
     return 0;
  }

  return 1;
}

int ossp_uuid_fmt(char *format, uuid_fmt_t *fmt, size_t *len)
{
  if (!strcmp(format, "binary")) {
    *fmt = UUID_FMT_BIN;
    *len = UUID_LEN_BIN;
  } else if (!strcmp(format, "text")) {
    *fmt = UUID_FMT_STR;
    *len = 0;
  } else {
    return 0;
  }

  return 1;
}

NIF(ossp_uuid_nif_make)
{
  uuid_t * uuid = NULL;
  char version[16];
  char format[16];
  ErlNifBinary result_binary = {0};
  uuid_fmt_t fmt = UUID_FMT_BIN;
  unsigned int mode = 0;
  char *buf = NULL;
  size_t len = 0;

  ERL_NIF_TERM result = enif_make_badarg(env);

  if (!enif_get_atom(env, argv[0], version, sizeof(version), ERL_NIF_LATIN1)) {
    return enif_make_badarg(env);
  }

  if (!enif_get_atom(env, argv[1], format, sizeof(version), ERL_NIF_LATIN1)) {
    return enif_make_badarg(env);
  }

  if (!ossp_uuid_mode(version, &mode)) {
    return enif_make_badarg(env);
  }

  if (!ossp_uuid_fmt(format, &fmt, &len)) {
    return enif_make_badarg(env);
  }

  if (uuid_create(&uuid) != UUID_RC_OK) {
    goto ERR;
  }

  switch (mode) {
    case UUID_MAKE_V1:
    case UUID_MAKE_V4:
          if (uuid_make(uuid, mode) != UUID_RC_OK) {
          goto ERR;
          }
          break;
    case UUID_MAKE_V3:
    case UUID_MAKE_V5:
          if (!make_uuid_ns(uuid, mode, env, argv)) {
          goto ERR;
          };
          break;
  }

  if (uuid_export(uuid, fmt, &buf, NULL) != UUID_RC_OK) {
    goto ERR;
  }

  if (!enif_alloc_binary( (len > 0 ? len : strlen(buf)),
              &result_binary)) {
    goto ERR;
  }
  (void)memcpy(result_binary.data, buf, result_binary.size);
  result = enif_make_binary(env, &result_binary);

ERR:
  if (buf) {
    free(buf);
  }

  if (uuid) {
    (void)uuid_destroy(uuid);
  }
  
  return result;
}


NIF(ossp_uuid_nif_import)
{
  uuid_t * uuid = NULL;
  ErlNifBinary binary = {0};
  char format[16];
  uuid_fmt_t fmt = UUID_FMT_BIN;
  ErlNifBinary result_binary = {0};
  char *buf = NULL;
  size_t len = 0;

  ERL_NIF_TERM result = enif_make_badarg(env);

  if (!enif_inspect_iolist_as_binary(env, argv[0], &binary)) {
      return enif_make_badarg(env);
  }

  if (!enif_get_atom(env, argv[1], format, sizeof(format), ERL_NIF_LATIN1)) {
    return enif_make_badarg(env);
  }

  if (!ossp_uuid_fmt(format, &fmt, &len)) {
    return enif_make_badarg(env);
  }

  if (uuid_create(&uuid) != UUID_RC_OK) {
    goto ERR;
  }

  switch (binary.size) {
      case UUID_LEN_BIN:
        if (uuid_import(uuid, UUID_FMT_BIN,
                    binary.data, binary.size) != UUID_RC_OK) {
        goto ERR;
        }
        break;
      case UUID_LEN_STR:
        if (uuid_import(uuid, UUID_FMT_STR,
                    binary.data, binary.size) != UUID_RC_OK) {
        goto ERR;
        }
        break;
      default:
        goto ERR;
  }

  if (uuid_export(uuid, fmt, &buf, NULL) != UUID_RC_OK) {
    goto ERR;
  }

  if (!enif_alloc_binary( (len > 0 ? len : strlen(buf)),
              &result_binary)) {
    goto ERR;
  }
  (void)memcpy(result_binary.data, buf, result_binary.size);
  result = enif_make_binary(env, &result_binary);

ERR:
  if (buf) {
    free(buf);
  }

  if (uuid) {
    (void)uuid_destroy(uuid);
  }
  
  return result;
}



static int on_load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info)
{
    return 0;
}

static int on_upgrade(ErlNifEnv* env, void** priv_data, void ** old_priv_data, ERL_NIF_TERM load_info)
{
    return 0;
}

ERL_NIF_INIT(ossp_uuid, nif_funcs, &on_load, NULL, &on_upgrade, NULL);
