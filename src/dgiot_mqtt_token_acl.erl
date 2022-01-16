-module(dgiot_mqtt_token_acl).

%% ACL Callbacks
-export([
    check_acl/5,
    description/0
    ]).

check_acl(ClientInfo = #{ clientid := _Clientid }, PubSub, _Topic, _NoMatchAction, _Params) ->
    _Username = maps:get(username, ClientInfo, undefined),
    Acls = [],
    case check_token(ClientInfo, PubSub, Acls) of
        allow ->
            ok;
        deny ->
              {stop, allow};
        _ ->
            ok
    end.

description() -> "toke Acl with Mnesia".

check_token(_ClientInfo,  _PubSub, []) ->
    none;
check_token(ClientInfo, PubSub, [ {_, ACLTopic, Action, Access, _} | Acls]) ->
    case match_actions(PubSub, Action) andalso do_check_token(ClientInfo, ACLTopic) of
        true -> Access;
        false -> check_token(ClientInfo, PubSub, Acls)
    end.

match_actions(subscribe, sub) -> true;
match_actions(publish, pub) -> true;
match_actions(_, _) -> false.

do_check_token(_ClientInfo = #{token := Token,username := Username,password:=Password}, Pattern) when Token =/= undefined->
    case binary:match(Pattern,<<"%t">>)of
        nomatch ->
            ok;
        _->
            case dgiot_auth:get_session(Token) of
                #{<<"username">> := Username, <<"password">> := Password} -> 
                    ok;
                _ -> deny
            end
    end.