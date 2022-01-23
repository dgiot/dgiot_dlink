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

check(#{username := Username}, AuthResult, _)
  when Username == <<"anonymous">> orelse Username =/= undefined ->
  {stop, AuthResult#{anonymous => true, auth_result => success}};

%% 当clientid 和 password 为token且相等的时候为用户登录
check(#{clientid := ClientID, username := Username, password := Password}, AuthResult, #{hash_type := _HashType})
  when ClientID == Password ->
  case dgiot_auth:get_session(ClientID) of
    #{<<"username">> := Username} ->
      {stop, AuthResult#{anonymous => false, auth_result => success}};
    _ ->
      {stop, AuthResult#{anonymous => false, auth_result => password_error}}
  end;

%% ClientID为deviceID , Username为ProductID
check(#{clientid := DeviceID, username := ProductID, password := Password}, AuthResult, #{hash_type := _HashType}) ->
  case dgiot_product:lookup_prod(ProductID) of
    {ok, #{<<"productSecret">> := Password}} ->
      {stop, AuthResult#{anonymous => false, auth_result => success}};
    _ ->
      case dgiot_device:lookup(DeviceID) of
        {ok, {[_, _, _Acl, _, _, _, Password], _}} ->
          {stop, AuthResult#{anonymous => false, auth_result => success}};
        _ ->
          {stop, AuthResult#{anonymous => false, auth_result => success}}
      end
  end;

check(_, AuthResult, _) ->
  {stop, AuthResult#{anonymous => false, auth_result => password_error}}.

description() -> "Authentication with Mnesia".