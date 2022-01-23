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

-module(dgiot_mqtt_acl).

%%-include("emqx_auth_mnesia.hrl").

%% ACL Callbacks
-export([
    check_acl/5
    , description/0
]).

check_acl(ClientInfo, PubSub, Topic, _NoMatchAction, _Params) ->
    _Username = maps:get(username, ClientInfo, undefined),
    Acls = [],
    case do_check(ClientInfo, PubSub, Topic, Acls) of
        allow ->
            ok;
%%            {stop, allow};
        deny ->
%%            {stop, deny};
            {stop, allow};
        _ ->
            ok
    end.

description() -> "Acl with Mnesia".

%%--------------------------------------------------------------------
%% Internal functions
%%-------------------------------------------------------------------

do_check(_ClientInfo, _PubSub, _Topic, []) ->
    ok;
do_check(ClientInfo, PubSub, Topic, [_ | Acls]) ->
    do_check(ClientInfo, PubSub, Topic, Acls);

%% 用户订阅 "$dg/user/deviceid/#"
do_check(#{clientid := ClientID, username := Username} = ClientInfo, subscribe, Topic, [{_, <<"$dg/user/", DeviceInfo/binary>>, sub, _Access, _} | Acls])
    when ClientID =/= undefined ->
    [DeviceID | _] = binary:split(DeviceInfo, <<"/">>),
    %% 此时的ClientID为 Token
    case check_device_acl(ClientID, DeviceID, Username) of
        ok ->
            do_check(ClientInfo, subscribe, Topic, Acls);
        _ ->
            deny
    end;
%%"$dg/device/productid/devaddr/#"
do_check(#{clientid := ClientID} = ClientInfo, subscribe, Topic, [{_, <<"$dg/device/", DeviceInfo/binary>>, sub, _Access, _} | Acls])
    ->
    [ProuctID, Devaddr | _] = binary:split(DeviceInfo, <<"/">>, [global]),
    DeviceID = dgiot_parse:get_deviceid(ProuctID, Devaddr),
    case ClientID == DeviceID of
        true ->
            do_check(ClientInfo, subscribe, Topic, Acls);
        _ ->
            deny
    end;

%%"$dg/thing/deviceid/#"
%%"$dg/thing/productid/devaddr/#"
do_check(#{clientid := ClientID, username := Username} = ClientInfo, publish, Topic, [{_, <<"$dg/thing/", DeviceInfo/binary>>, pub, _Access, _} | Acls])
    when ClientID =/= undefined ->
    [ID, Devaddr | _] = binary:split(DeviceInfo, <<"/">>, [global]),
    %% 先判断clientid为Token
    case check_device_acl(ClientID, ID, Username) of
        ok ->
            do_check(ClientInfo, publish, Topic, Acls);
        _ ->
            DeviceID = dgiot_parse:get_deviceid(ID, Devaddr),
            case ClientID == DeviceID of
                true ->
                    do_check(ClientInfo, publish, Topic, Acls);
                _ ->
                    deny
            end
    end;

do_check(ClientInfo, PubSub, Topic, [_ | Acls]) ->
    do_check(ClientInfo, PubSub, Topic, Acls).

check_device_acl(Token, DeviceID, UserName) ->
    {TUsername, Acl} =
        case dgiot_auth:get_session(Token) of
            #{<<"username">> := Name, <<"ACL">> := Acl1} -> {Name, Acl1};
            _ -> {<<"">>, #{}}
        end,
    case TUsername == UserName of
        true ->
            DeviceAcl = dgiot_device:get_acl(DeviceID),
            case DeviceAcl == Acl of
                true ->
                    ok;
                _ ->
                    deny
            end;
        _ ->
            deny
    end.
