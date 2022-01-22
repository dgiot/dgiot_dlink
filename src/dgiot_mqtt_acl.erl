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

match(_ClientInfo, _PubSub, _Topic, []) ->
  nomatch;
match(ClientInfo, PubSub, Topic, [_ | Acls]) ->
  match(ClientInfo, PubSub, Topic, Acls);

match(ClientInfo, PubSub, Topic, [{_, ACLTopic, Action, Access, _} | Acls]) ->
  case match_actions(PubSub, Action) andalso match_topic(ClientInfo, Topic, ACLTopic) of
    true -> Access;
    false -> match(ClientInfo, PubSub, Topic, Acls)
  end.

match_topic(ClientInfo, Topic, ACLTopic) when is_binary(Topic) ->
  {Acc, Token} = feed_var(ClientInfo, ACLTopic),
  MatchResult = emqx_topic:match(Topic, Acc),
  case Token == undefined of
    true ->
      MatchResult;
    _ ->
      Username = maps:get(username, ClientInfo, undefined),
      Password = maps:get(password, ClientInfo, undefined),
      case dgiot_auth:get_session(Token) of
        #{<<"username">> := Username, <<"password">> := Password} ->
          MatchResult;
        _ -> false
      end
  end.

match_actions(subscribe, sub) -> true;
match_actions(publish, pub) -> true;
match_actions(_, _) -> false.

feed_var(ClientInfo, Pattern) ->
  feed_var(ClientInfo, emqx_topic:words(Pattern), [], undefined).
feed_var(_ClientInfo, [], Acc, TokenAcc) ->
  {emqx_topic:join(lists:reverse(Acc)), TokenAcc};
feed_var(ClientInfo = #{clientid := undefined}, [<<"%c">> | Words], Acc, TokenAcc) ->
  feed_var(ClientInfo, Words, [<<"%c">> | Acc], TokenAcc);
feed_var(ClientInfo = #{clientid := ClientId}, [<<"%c">> | Words], Acc, TokenAcc) ->
  feed_var(ClientInfo, Words, [ClientId | Acc], TokenAcc);
feed_var(ClientInfo = #{username := undefined}, [<<"%u">> | Words], Acc, TokenAcc) ->
  feed_var(ClientInfo, Words, [<<"%u">> | Acc], TokenAcc);
feed_var(ClientInfo = #{username := Username}, [<<"%u">> | Words], Acc, TokenAcc) ->
  feed_var(ClientInfo, Words, [Username | Acc], TokenAcc);
feed_var(ClientInfo = #{password := Token}, [<<"%t">> | Words], Acc, TokenAcc) when TokenAcc == undefined ->
  feed_var(ClientInfo, Words, Acc, Token);

feed_var(ClientInfo, [W | Words], Acc, TokenAcc) ->
  feed_var(ClientInfo, Words, [W | Acc], TokenAcc).
