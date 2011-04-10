#include "uuid.h"
#include "erl_nif.h"
#include <string.h>

// Prototypes
#define NIF(name) ERL_NIF_TERM name(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])

NIF(ossp_uuid_nif_make);
NIF(ossp_uuid_nif_import);

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
  uuid_t *uuid_ns;
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

  uuid_create(&uuid_ns);
  uuid_load(uuid_ns, ns);

  uuid_make(uuid, mode, uuid_ns, name);

  uuid_destroy(uuid_ns);

  ret = 1;

ERR:
  if (ns) {
    free(ns);
  }

  if (name) {
    free(name);
  }

  return ret;
}


NIF(ossp_uuid_nif_make)
{
  uuid_t * uuid;
  char version[16];
  char format[16];
  ERL_NIF_TERM result;

  if (!enif_get_atom(env, argv[0], version, sizeof(version), ERL_NIF_LATIN1)) {
    return enif_make_badarg(env);
  }

  if (!enif_get_atom(env, argv[1], format, sizeof(version), ERL_NIF_LATIN1)) {
    return enif_make_badarg(env);
  }

  uuid_create(&uuid);

  if (!strcmp(version,"v1")) {
    uuid_make(uuid, UUID_MAKE_V1);
  } else if (!strcmp(version,"v3")) {
    if (!make_uuid_ns(uuid, UUID_MAKE_V3, env, argv)) {
          return enif_make_badarg(env);
    }
  } else if (!strcmp(version,"v4")) {
    uuid_make(uuid, UUID_MAKE_V4);
  } else if (!strcmp(version,"v5")) {
    if (!make_uuid_ns(uuid, UUID_MAKE_V5, env, argv)) {
          return enif_make_badarg(env);
    }  
  } else {
    return enif_make_badarg(env);
  }

  
  ErlNifBinary result_binary;

  if (!strcmp(format, "binary")) {
    size_t len = UUID_LEN_BIN;
    if (!enif_alloc_binary(UUID_LEN_BIN, &result_binary)) {
          return enif_make_badarg(env);
    }
    uuid_export(uuid, UUID_FMT_BIN, &result_binary.data, &len);
    result = enif_make_binary(env, &result_binary);
  } else if (!strcmp(format, "text")) {
    char *buf = NULL;
    uuid_export(uuid, UUID_FMT_STR, &buf, NULL);
    if (!enif_alloc_binary(strlen(buf), &result_binary)) {
          return enif_make_badarg(env);
    }
    (void)memcpy(result_binary.data, buf, result_binary.size);
    result = enif_make_binary(env, &result_binary);
    free(buf);
  } else {
    result = enif_make_badarg(env);
  }

  uuid_destroy(uuid);
  
  return result;
}


NIF(ossp_uuid_nif_import)
{
  uuid_t * uuid;
  ErlNifBinary binary;
  ERL_NIF_TERM result;
  char format[16];

  if (!enif_inspect_iolist_as_binary(env, argv[0], &binary)) {
      return enif_make_badarg(env);
  }

  if (!enif_get_atom(env, argv[1], (char *) &format, sizeof(format), ERL_NIF_LATIN1)) {
    return enif_make_badarg(env);
  }

  uuid_create(&uuid);

  if (binary.size == UUID_LEN_BIN) {
    uuid_import(uuid, UUID_FMT_BIN, (void *)binary.data, binary.size);
  } else if (binary.size == UUID_LEN_STR) {
    uuid_import(uuid, UUID_FMT_STR, (void *)binary.data, binary.size);
  } else {
    return enif_make_badarg(env);
  }


  ErlNifBinary result_binary;

  if (!strcmp(format, "binary")) {
    size_t len = UUID_LEN_BIN;
    if (!enif_alloc_binary(UUID_LEN_BIN, &result_binary)) {
          return enif_make_badarg(env);
    }
    uuid_export(uuid, UUID_FMT_BIN, &result_binary.data, &len);
    result = enif_make_binary(env, &result_binary);
  } else if (!strcmp(format, "text")) {
    char *buf = NULL;
    uuid_export(uuid, UUID_FMT_STR, &buf, NULL);
    if (!enif_alloc_binary(strlen(buf), &result_binary)) {
          return enif_make_badarg(env);
    }
    (void)memcpy(result_binary.data, buf, result_binary.size);
    result = enif_make_binary(env, &result_binary);
    free(buf);
  } else {
    result = enif_make_badarg(env);
  }

  uuid_destroy(uuid);
  
  return result;
}



static int on_load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info)
{
    return 0;
}

ERL_NIF_INIT(ossp_uuid, nif_funcs, &on_load, NULL, NULL, NULL);
