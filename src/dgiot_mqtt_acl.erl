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

check_acl(ClientInfo = #{ clientid := _Clientid }, PubSub, Topic, _NoMatchAction, _Params) ->
    _Username = maps:get(username, ClientInfo, undefined),
    Acls = [],
    case match(ClientInfo, PubSub, Topic, Acls) of
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

match(_ClientInfo,  _PubSub, _Topic, []) ->
    nomatch;
match(ClientInfo, PubSub, Topic, [ {_, ACLTopic, Action, Access, _} | Acls]) ->
    case match_actions(PubSub, Action) andalso match_topic(ClientInfo, Topic, ACLTopic) of
        true -> Access;
        false -> match(ClientInfo, PubSub, Topic, Acls)
    end.

match_topic(ClientInfo, Topic, ACLTopic) when is_binary(Topic) ->
    emqx_topic:match(Topic, feed_var(ClientInfo, ACLTopic)).

match_actions(subscribe, sub) -> true;
match_actions(publish, pub) -> true;
match_actions(_, _) -> false.

feed_var(ClientInfo, Pattern) ->
    feed_var(ClientInfo, emqx_topic:words(Pattern), []).
feed_var(_ClientInfo, [], Acc) ->
    emqx_topic:join(lists:reverse(Acc));
feed_var(ClientInfo = #{clientid := undefined}, [<<"%c">>|Words], Acc) ->
    feed_var(ClientInfo, Words, [<<"%c">>|Acc]);
feed_var(ClientInfo = #{clientid := ClientId}, [<<"%c">>|Words], Acc) ->
    feed_var(ClientInfo, Words, [ClientId |Acc]);
feed_var(ClientInfo = #{username := undefined}, [<<"%u">>|Words], Acc) ->
    feed_var(ClientInfo, Words, [<<"%u">>|Acc]);
feed_var(ClientInfo = #{username := Username}, [<<"%u">>|Words], Acc) ->
    feed_var(ClientInfo, Words, [Username|Acc]);
feed_var(ClientInfo, [W|Words], Acc) ->
    feed_var(ClientInfo, Words, [W|Acc]).
