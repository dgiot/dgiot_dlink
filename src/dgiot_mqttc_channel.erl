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
-module(dgiot_mqttc_channel).
-behavior(dgiot_channelx).
-define(TYPE, <<"MQTTC">>).
-author("kenneth").
-record(state, {id, client = disconnect}).
-include_lib("dgiot_bridge/include/dgiot_bridge.hrl").
-include_lib("dgiot/include/logger.hrl").
-include("dgiot_dlink.hrl").

%% API
-dgiot_data("ets").
-export([init_ets/0]).

-export([start/2]).
-export([init/3, handle_event/3, handle_message/2, handle_init/1, stop/3]).
-export([init/1, handle_info/2, handle_cast/2, handle_call/3, terminate/2, code_change/3]).


%% 注册通道类型
-channel_type(#{
    cType => ?TYPE,
    type => ?PROTOCOL_CHL,
    title => #{
        zh => <<"MQTT资源通道"/utf8>>
    },
    description => #{
        zh => <<"MQTT资源通道"/utf8>>
    }
}).
%% 注册通道参数
-params(#{
    <<"address">> => #{
        order => 1,
        type => string,
        required => true,
        default => <<"127.0.0.1">>,
        title => #{
            zh => <<"主机地址"/utf8>>
        },
        description => #{
            zh => <<"主机地址"/utf8>>
        }
    },
    <<"port">> => #{
        order => 2,
        type => integer,
        required => true,
        default => 1883,
        title => #{
            zh => <<"端口"/utf8>>
        },
        description => #{
            zh => <<"端口"/utf8>>
        }
    },
    <<"username">> => #{
        order => 3,
        type => string,
        required => true,
        default => <<"test"/utf8>>,
        title => #{
            zh => <<"用户名"/utf8>>
        },
        description => #{
            zh => <<"用户名"/utf8>>
        }
    },
    <<"password">> => #{
        order => 4,
        type => string,
        required => true,
        default => <<"test"/utf8>>,
        title => #{
            zh => <<"密码"/utf8>>
        },
        description => #{
            zh => <<"密码"/utf8>>
        }
    },
    <<"ssl">> => #{
        order => 6,
        type => boolean,
        required => true,
        default => false,
        title => #{
            zh => <<"SSL"/utf8>>
        },
        description => #{
            zh => <<"是否使用SSL"/utf8>>
        }
    },
    <<"clean_start">> => #{
        order => 7,
        type => boolean,
        required => true,
        default => false,
        title => #{
            zh => <<"清除会话"/utf8>>
        },
        description => #{
            zh => <<"是否清除会话"/utf8>>
        }
    },
    <<"ico">> => #{
        order => 102,
        type => string,
        required => false,
        default => <<"http://dgiot-1253666439.cos.ap-shanghai-fsi.myqcloud.com/shuwa_tech/zh/product/dgiot/channel/MQTT.png">>,
        title => #{
            en => <<"channel ICO">>,
            zh => <<"通道ICO"/utf8>>
        },
        description => #{
            en => <<"channel ICO">>,
            zh => <<"通道ICO"/utf8>>
        }
    }
}).

init_ets() ->
    dgiot_data:init(?DGIOT_MQTT_WORK).

start(ChannelId, ChannelArgs) ->
    dgiot_channelx:add(?TYPE, ChannelId, ?MODULE, ChannelArgs).

%% 通道初始化
init(?TYPE, ChannelId, ChannelArgs) ->
    Options = [
        {host, binary_to_list(maps:get(<<"address">>, ChannelArgs))},
        {port, maps:get(<<"port">>, ChannelArgs)},
        {clientid, ChannelId},
        {ssl, maps:get(<<"ssl">>, ChannelArgs, false)},
        {username, binary_to_list(maps:get(<<"username">>, ChannelArgs))},
        {password, binary_to_list(maps:get(<<"password">>, ChannelArgs))},
        {clean_start, maps:get(<<"clean_start">>, ChannelArgs, false)}
    ],

    State = #state{
        id = ChannelId
    },
    Specs = [
        {dgiot_mqtt_client, {dgiot_mqtt_client, start_link, [?MODULE, [State], Options]}, permanent, 5000, worker, [dgiot_mqtt_client]}
    ],
    {ok, State, Specs}.

%% 初始化池子
handle_init(State) ->
    {ok, State}.

%% 通道消息处理,注意：进程池调用
handle_event(EventId, Event, _State) ->
    ?LOG(info, "channel ~p, ~p", [EventId, Event]),
    ok.

handle_message(Message, State) ->
    ?LOG(info, "channel ~p", [Message]),
    {ok, State}.


stop(ChannelType, ChannelId, _State) ->
    ?LOG(info, "channel stop ~p,~p", [ChannelType, ChannelId]),
    ok.


%% mqtt client hook
init([State]) ->
    {ok, State#state{}}.

handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast(_Request, State) ->
    {noreply, State}.

handle_info({connect, Client}, #state{id = ChannelId} = State) ->
    case dgiot_bridge:get_products(ChannelId) of
        {ok, _Type, ProductIds} ->
            case ProductIds of
                [] -> pass;
                _ ->
                    lists:map(fun(ProductId) ->
%%                        dgiot_product:load(ProductId),
                        emqtt:subscribe(Client, {<<"bridge/thing/", ProductId/binary, "/#">>, 1}),
                        dgiot_mqtt:subscribe(<<"forward/thing/", ProductId/binary, "/+/post">>),
                        dgiot_mqtt:publish(ChannelId, <<"thing/", ProductId/binary>>, jsx:encode(#{<<"network">> => <<"connect">>}))
                              end, ProductIds)
            end,
            ?LOG(info, "connect ~p sub ~n", [Client]);
        _ -> pass
    end,
    {noreply, State#state{client = Client}};

handle_info(disconnect, #state{id = ChannelId} = State) ->
    case dgiot_bridge:get_products(ChannelId) of
        {ok, _Type, ProductIds} ->
            case ProductIds of
                [] -> pass;
                _ ->
                    lists:map(fun(ProductId) ->
                        dgiot_mqtt:publish(ChannelId, <<"thing/", ProductId/binary>>, jsx:encode(#{<<"network">> => <<"disconnect">>}))
                              end, ProductIds)
            end;
        _ -> pass
    end,
    {noreply, State#state{client = disconnect}};

handle_info({publish, #{payload := Payload, topic := <<"bridge/", Topic/binary>>} = _Msg}, #state{id = ChannelId} = State) ->
    dgiot_mqtt:publish(ChannelId, Topic, Payload),
    {noreply, State};

handle_info({deliver, _, Msg}, #state{client = Client} = State) ->
    case dgiot_mqtt:get_topic(Msg) of
        <<"forward/", Topic/binary>> -> emqtt:publish(Client, Topic, dgiot_mqtt:get_payload(Msg));
        _ -> pass
    end,
    {noreply, State};

handle_info(Info, State) ->
    ?LOG(info, "unkknow ~p~n", [Info]),
    {noreply, State}.


terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.
