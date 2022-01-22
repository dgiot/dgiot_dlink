%%--------------------------------------------------------------------
%% Copyright (c) 2020-2021 DGIOT Technologies Co., Ltd. All Rights Reserved.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%--------------------------------------------------------------------

-module(dgiot_mqtt_auth).

%%-include("emqx_auth_mnesia.hrl").
%%
%%-include_lib("emqx/include/emqx.hrl").
%%-include_lib("emqx/include/logger.hrl").
%%-include_lib("emqx/include/types.hrl").
%%
%%-include_lib("stdlib/include/ms_transform.hrl").
%%
-define(TABLE, emqx_user).
%% Auth callbacks
-export([
  check/3
  , description/0
]).


check(#{username := Username, token := Token}, AuthResult, #{hash_type := _HashType})
  when Username =/= undefined ->

  case dgiot_auth:get_session(Token) of
    #{<<"username">> := Username} ->
      {stop, AuthResult#{anonymous => false, auth_result => success}};
    _ ->
      {stop, AuthResult#{anonymous => false, auth_result => password_error}}
  end;
check(_, AuthResult, _) ->
  {stop, AuthResult#{anonymous => false, auth_result => password_error}}.

description() -> "Authentication with Mnesia".