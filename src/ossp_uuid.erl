-module(ossp_uuid).

-export([make/2, make/4, import/2]).

-on_load(init/0).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

init() ->
  case code:priv_dir(ossp_uuid) of
    {error, bad_name} ->
          erlang:load_nif(filename:join([filename:dirname(code:which(?MODULE)), "..", "priv", "ossp_uuid_drv"]), []);
    Dir ->
          erlang:load_nif(filename:join([Dir, "ossp_uuid_drv"]), [])
  end.

%% ----------------------------------
%% @doc 
%% Generate UUID
%% @spec make(Version::(v1|v4), Format::text|binary) -> binary()
%% @end
%% ----------------------------------
make(_Mode, _Format) ->
    erlang:nif_error(not_loaded).

%% ----------------------------------
%% @doc 
%% Generate UUID
%% @spec make(Version::(v3|v5), Format::text|binary, NS::string(), Name::string()) -> binary()
%% @end
%% ----------------------------------
make(_Mode, _Format, _NS, _Name) ->
    erlang:nif_error(not_loaded).

%% ----------------------------------
%% @doc 
%% Import UUID
%% @spec import(UUID::iolist(), Format::text|binary) -> binary()
%% @end
%% ----------------------------------
import(_IOList, _Format) ->
    erlang:nif_error(not_loaded).

%% ===================================================================
%% EUnit tests
%% ===================================================================
-ifdef(TEST).

make_v1_test() ->
    B1 = make(v1, binary),
    ?assert(is_binary(B1)),
    ?assertEqual(16, size(B1)),
    S1 = make(v1, text),
    ?assertEqual(36, size(S1)).

make_v3_test() ->
    B1 = make(v3, binary, "ns:URL", "http://example.org"),
    ?assert(is_binary(B1)),
    ?assertEqual(16, size(B1)),
    ?assertEqual(B1,  make(v3, binary, "ns:URL", "http://example.org")),
    S1 = make(v3, text, "ns:URL", "http://example.org"),
    ?assertEqual(36, size(S1)),
    ?assertEqual(S1,  make(v3, text, "ns:URL", "http://example.org")).

make_v4_test() ->
    B1 = make(v4, binary),
    ?assert(is_binary(B1)),
    ?assertEqual(16, size(B1)),
    S1 = make(v4, text),
    ?assertEqual(36, size(S1)).

make_v5_test() ->
    B1 = make(v5, binary, "ns:URL", "http://example.org"),
    ?assert(is_binary(B1)),
    ?assertEqual(16, size(B1)),
    ?assertEqual(B1,  make(v5, binary, "ns:URL", "http://example.org")),
    S1 = make(v5, text, "ns:URL", "http://example.org"),
    ?assertEqual(36, size(S1)),
    ?assertEqual(S1,  make(v5, text, "ns:URL", "http://example.org")).


import_v1_test() ->
    B1 = make(v1, binary),
    S1 = make(v1, text),
    ?assertEqual(B1, import(B1, binary)),
    ?assertEqual(import(B1, text), import(import(B1, binary), text)),
    ?assertEqual(S1, import(S1, text)),
    ?assertEqual(import(S1, binary), import(import(S1, text), binary)).

import_v3_test() ->
    B1 = make(v3, binary,"ns:URL", "http://example.org"),
    S1 = make(v3, text,"ns:URL", "http://example.org"),
    ?assertEqual(B1, import(B1, binary)),
    ?assertEqual(import(B1, text), import(import(B1, binary), text)),
    ?assertEqual(S1, import(S1, text)),
    ?assertEqual(import(S1, binary), import(import(S1, text), binary)).

import_v4_test() ->
    B1 = make(v4, binary),
    S1 = make(v4, text),
    ?assertEqual(B1, import(B1, binary)),
    ?assertEqual(import(B1, text), import(import(B1, binary), text)),
    ?assertEqual(S1, import(S1, text)),
    ?assertEqual(import(S1, binary), import(import(S1, text), binary)).

import_v5_test() ->
    B1 = make(v5, binary,"ns:URL", "http://example.org"),
    S1 = make(v5, text,"ns:URL", "http://example.org"),
    ?assertEqual(B1, import(B1, binary)),
    ?assertEqual(import(B1, text), import(import(B1, binary), text)),
    ?assertEqual(S1, import(S1, text)),
    ?assertEqual(import(S1, binary), import(import(S1, text), binary)).
    
    

-endif.
