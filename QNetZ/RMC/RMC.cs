using QNetZ.DDL;
using QNetZ.Factory;
using QNetZ.Interfaces;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;

namespace QNetZ
{
	public static class RMC
	{
		public static void HandlePacket(QPacketHandlerPRUDP handler, QPacket p, QClient client)
		{
			client.SessionID = p.m_bySessionID;

			if (p.uiSeqId > client.SeqCounter)
				client.SeqCounter = p.uiSeqId;

			if (QRVPacket.IsQRVFormat(p.payload))
			{
				HandleQRVPacket(handler, client, p);
				return;
			}

			var rmc = new RMCPacket(p);
			if (rmc.isRequest)
				HandleRequest(handler, client, p, rmc);
			else
				HandleResponse(handler, client, p, rmc);
		}

		private static void HandleQRVPacket(QPacketHandlerPRUDP handler, QClient client, QPacket p)
		{
			var qrv = new QRVPacket(p.payload);

			var clientName = client.PlayerInfo != null ? client.PlayerInfo.Name : "<unkClient>";
			QLog.WriteLine(2, $"[QRV] ({clientName}) {(qrv.IsRequest ? "Request" : "Response")}: {qrv}");

			if (!qrv.IsRequest)
			{
				handler.SendACK(p, client);
				return;
			}

			handler.SendACK(p, client);

			byte[] responseData = null;
			bool handled = true;

			switch (qrv.MethodName)
			{
				case "SimpleAuthenticationProtocol::LoginWithToken_V2":
					responseData = HandleLoginWithToken_V2(client);
					break;
				case "SimpleAuthenticationProtocol::Register_V1":
					responseData = HandleRegister_V1(client, qrv);
					break;

				// -- Post-auth init --
				case "GameConfigProtocol::GetConfig_V2":
					responseData = new byte[] { 0x00, 0x00, 0x00, 0x00 }; // empty config map
					break;

				case "Tracking2Protocol::GetStartupStats_V1":
					break; // empty success

				case "PrivilegesProtocol::GetPrivileges_V1":
					responseData = HandleGetPrivileges_V1();
					break;

				case "LocalizationProtocol::SetLocaleCode_V1":
					break; // empty success

				case "PrivilegesProtocol::ActivateKey_V1":
					break; // accept any DLC key

				// -- Social / UI data --
				case "NewsProtocol::GetNewsByChannelType_V1":
					responseData = new byte[] { 0x00, 0x00, 0x00, 0x00 }; // empty list
					break;

				case "FriendSyncProtocol::SyncFriends_V1":
					break; // empty success

				case "TransactionProtocol::GetUnverifiedTransactions_V3":
					responseData = new byte[] { 0x00, 0x00, 0x00, 0x00 }; // empty list
					break;

				case "LeaderboardsProtocol::GetLeaderboardOverviewWithEstimatedUserPositionAndDefaultSorting_V2":
					break; // empty success

				// -- Session / Matchmaking --
				case "GameSessionProtocol::RegisterURLs_V1":
					HandleRegisterURLs_V1(client, qrv);
					break;

				case "ServerMatchMakingProtocol::SetPlayerBlocklist_V1":
					break; // empty success

				case "ServerMatchMakingProtocol::SetPlayerAvailableForMatchMaking_V5":
					break; // empty success (no match on private server)

				case "ServerMatchMakingProtocol::CancelMatchmakingRequest_V1":
					break; // empty success

				case "GameSessionProtocol::CreateSession_V1":
					responseData = HandleCreateSession_V1(client, qrv);
					break;

				case "GameSessionProtocol::AddParticipants_V1":
					break; // empty success

				default:
					QLog.WriteLine(1, $"[QRV] Unhandled method: {qrv.MethodName}");
					handled = false;
					break;
			}

			if (!handled)
				return;

			SendQRVResponse(handler, p, client, qrv.MakeSuccessResponse(responseData));
		}

		private static byte[] HandleLoginWithToken_V2(QClient client)
		{
			var playerInfo = NetworkPlayers.CreatePlayerInfo(client);
			playerInfo.PID = 2;
			playerInfo.AccountId = "00000000-0000-0000-0000-000000000001";
			playerInfo.Name = "Player1";

			client.PlayerInfo = playerInfo;
			playerInfo.Client = client;

			QLog.WriteLine(1, $"[QRV] LoginWithToken_V2: logged in as PID={playerInfo.PID} name={playerInfo.Name}");

			var m = new MemoryStream();

			// 16-byte opaque auth blob (zeros — server accepts any on reconnect)
			m.Write(new byte[16], 0, 16);

			// Station URL 1: our server (client will connect/continue here)
			var host = QConfiguration.Instance.ServiceURLHostName
				?? QConfiguration.Instance.ServerBindAddress
				?? "127.0.0.1";
			var port = QConfiguration.Instance.RDVServerPort;
			var url1 = $"prudp:/address={host};port={port};CID=1;PID={playerInfo.PID};sid=1;stream=3;type=2";
			var url1Bytes = Encoding.ASCII.GetBytes(url1 + "\0");
			Helper.WriteU16(m, (ushort)url1Bytes.Length);
			m.Write(url1Bytes, 0, url1Bytes.Length);

			// 4 zero bytes (padding / reserved)
			Helper.WriteU32(m, 0);

			// Station URL 2: minimal fallback
			var url2Bytes = Encoding.ASCII.GetBytes("prudp:/\0");
			Helper.WriteU16(m, (ushort)url2Bytes.Length);
			m.Write(url2Bytes, 0, url2Bytes.Length);

			// 4 zero bytes (padding / reserved)
			Helper.WriteU32(m, 0);

			return m.ToArray();
		}

		private static byte[] HandleRegister_V1(QClient client, QRVPacket qrv)
		{
			// Parse the client's station URL from parameters
			// Format: [U32 reserved][U32 url_count][U16 url_len][url\0]...
			var m = new MemoryStream(qrv.ParameterData);
			Helper.ReadU32(m); // reserved
			uint urlCount = Helper.ReadU32(m);
			string clientUrl = null;
			for (uint i = 0; i < urlCount; i++)
			{
				ushort urlLen = Helper.ReadU16(m);
				var urlBytes = new byte[urlLen];
				m.Read(urlBytes, 0, urlLen);
				var url = Encoding.ASCII.GetString(urlBytes).TrimEnd('\0');
				QLog.WriteLine(1, $"[QRV] Register_V1: client URL[{i}] = {url}");
				if (i == 0) clientUrl = url;
			}

			// Response: retVal=0 (success), CID=1, plus the client's public station URL
			var resp = new MemoryStream();
			Helper.WriteU32(resp, 0); // retVal = success
			Helper.WriteU32(resp, 1); // CID
			// Echo client URL back as public station URL (required by Quazal Register protocol)
			var publicUrl = clientUrl ?? "prudp:/";
			var publicUrlBytes = Encoding.ASCII.GetBytes(publicUrl + "\0");
			Helper.WriteU16(resp, (ushort)publicUrlBytes.Length);
			resp.Write(publicUrlBytes, 0, publicUrlBytes.Length);
			return resp.ToArray();
		}
		private static byte[] HandleGetPrivileges_V1()
		{
			// Return minimal privilege list: privilege ID=1 (online access), is_active=1
			// Format mirrors how the real server responds: U32 count + [U32 id + U8 active] per privilege
			var m = new MemoryStream();
			Helper.WriteU32(m, 1);  // count = 1
			Helper.WriteU32(m, 1);  // privilege_id = 1 (online multiplayer)
			Helper.WriteU8(m, 1);   // is_active = true
			return m.ToArray();
		}

		private static void HandleRegisterURLs_V1(QClient client, QRVPacket qrv)
		{
			// Parse and log the client P2P URLs
			// Format: [U32 NamPro count=0] [U32 url_count] [U16 url_len][url\0]...
			var m = new MemoryStream(qrv.ParameterData);
			Helper.ReadU32(m); // NamPro count
			uint urlCount = Helper.ReadU32(m);
			for (uint i = 0; i < urlCount; i++)
			{
				ushort urlLen = Helper.ReadU16(m);
				var urlBytes = new byte[urlLen];
				m.Read(urlBytes, 0, urlLen);
				var url = System.Text.Encoding.ASCII.GetString(urlBytes).TrimEnd('\0');
				QLog.WriteLine(1, $"[QRV] RegisterURLs_V1: client URL[{i}] = {url}");
			}
		}

		private static uint _nextSessionId = 0x00010001;

		private static byte[] HandleCreateSession_V1(QClient client, QRVPacket qrv)
		{
			uint sessionId = _nextSessionId++;
			QLog.WriteLine(1, $"[QRV] CreateSession_V1: session={sessionId:X8} player={client.PlayerInfo?.Name}");
			// Return 8-byte session key (U32 low + U32 high)
			var m = new MemoryStream();
			Helper.WriteU32(m, sessionId);
			Helper.WriteU32(m, 0);
			return m.ToArray();
		}

		private static void SendQRVResponse(QPacketHandlerPRUDP handler, QPacket p, QClient client, byte[] responseBytes)
		{
			var np = new QPacket(p.toBuffer());
			np.flags = new List<QPacket.PACKETFLAG>() { QPacket.PACKETFLAG.FLAG_NEED_ACK, QPacket.PACKETFLAG.FLAG_RELIABLE };
			np.m_oSourceVPort = p.m_oDestinationVPort;
			np.m_oDestinationVPort = p.m_oSourceVPort;
			np.m_uiSignature = client.IDsend;
			np.usesCompression = false;

			handler.MakeAndSend(client, p, np, responseBytes);
		}

		public static void HandleResponse(QPacketHandlerPRUDP handler, QClient client, QPacket p, RMCPacket rmc)
		{
			WriteLog(client, 2, $"Received Response : {rmc}");
			var message = (rmc.success ? "Success" : $"Fail : {rmc.error.ToString("X8")} for callID = {rmc.callID}");
			WriteLog(client, 2, $"Got response for {rmc.proto} = {message}");

			handler.SendACK(p, client);
		}

		public static void HandleRequest(QPacketHandlerPRUDP handler, QClient client, QPacket p, RMCPacket rmc)
		{
			if (rmc.callID > client.CallCounterRMC)
				client.CallCounterRMC = rmc.callID;

			WriteLog(client, 2, "Request : " + rmc.ToString());

			MemoryStream m = new MemoryStream(p.payload);
			m.Seek(rmc._afterProtocolOffset, SeekOrigin.Begin);

			var rmcContext = new RMCContext(rmc, handler, client, p);

			// create service instance
			var serviceFactory = RMCServiceFactory.GetServiceFactory(rmc.proto);

			if (serviceFactory == null)
			{
				WriteLog(client, 1, $"Error: No service registered for packet protocol '{rmc.proto}' (protocolId = {(int)rmc.proto})");
				SendResponseWithACK(handler, rmcContext.Packet, rmc, client, new RMCPResponseEmpty(), false, (uint)Connection.ErrorCode.Core_NotImplemented);
				return;
			}

			// set the execution context
			var serviceInstance = serviceFactory();

			serviceInstance.Context = rmcContext;
			var bestMethod = serviceInstance.GetServiceMethodById(rmc.methodID);

			if (bestMethod == null)
			{
				WriteLog(client, 1, $"Error: No method '{ rmc.methodID }' registered for protocol '{ rmc.proto }'");
				SendResponseWithACK(handler, rmcContext.Packet, rmc, client, new RMCPResponseEmpty(), false, (uint)Connection.ErrorCode.Core_NotImplemented);
				return;
			}

			// try invoke method method
			// TODO: extended info
			var typeList = bestMethod.GetParameters().Select(x => x.ParameterType);
			var parameters = DDLSerializer.ReadPropertyValues(typeList.ToArray(), m);

			WriteLog(client, 5, () => "Request parameters: " + DDLSerializer.ObjectToString(parameters));

			try
			{
				var returnValue = bestMethod.Invoke(serviceInstance, parameters);

				if (returnValue != null)
				{
					if (typeof(RMCResult).IsAssignableFrom(returnValue.GetType()))
					{
						var rmcResult = (RMCResult)returnValue;

						SendResponseWithACK(
							handler,
							rmcContext.Packet,
							rmcContext.RMC,
							rmcContext.Client,
							rmcResult.Response,
							rmcResult.Compression, rmcResult.Error);
					}
					else
					{
						// TODO: try to cast and create RMCPResponseDDL???
						throw new Exception("something other than RMCResult is cannot be sent yet");
					}
				} else {
					handler.SendACK(rmcContext.Packet, client);
				}
			}
			catch (TargetInvocationException tie)
			{
				handler.SendACK(rmcContext.Packet, client);

				WriteLog(client, 1, $"Error: exception occurred in {rmc.proto}.{bestMethod.Name}");
				var inner = tie.InnerException;
				if (inner != null)
                {
					WriteLog(client, 1, $"Error: {inner.Message}");

					if (inner.StackTrace != null)
						WriteLog(client, 1, $"Error: { inner.StackTrace }");
				}
			}
		}

		public static void SendResponseWithACK(QPacketHandlerPRUDP handler, QPacket p, RMCPacket rmc, QClient client, RMCPResponse reply, bool useCompression = true, uint error = 0)
		{
			WriteLog(client, 2, "Response : " + reply.ToString());
			WriteLog(client, 4, () => "Response data : \n" + reply.PayloadToString());

			handler.SendACK(p, client);

			SendResponsePacket(handler, p, rmc, client, reply, useCompression, error);
		}

		public static void SendRMCCall(QPacketHandlerPRUDP handler, QClient client, RMCProtocolId protoId, uint methodId, RMCPRequest requestData)
		{
			var packet = new QPacket();

			packet.m_oSourceVPort = new QPacket.VPort(0x31);
			packet.m_oDestinationVPort = new QPacket.VPort(0x3f);

			packet.type = QPacket.PACKETTYPE.DATA;
			packet.flags = new List<QPacket.PACKETFLAG>() { QPacket.PACKETFLAG.FLAG_RELIABLE | QPacket.PACKETFLAG.FLAG_NEED_ACK };
			packet.payload = new byte[0];
			packet.m_bySessionID = client.SessionID;

			var rmc = new RMCPacket();

			rmc.proto = protoId;
			rmc.methodID = methodId;

			WriteLog(client, 2, $"Sending call { protoId }.{ methodId }");
			WriteLog(client, 4, () => "Call data : " + requestData.PayloadToString());

			SendRequestPacket(handler, packet, rmc, client, requestData, true, 0);
		}

		private static void SendResponsePacket(QPacketHandlerPRUDP handler, QPacket p, RMCPacket rmc, QClient client, RMCPResponse reply, bool useCompression, uint error)
		{
			rmc.isRequest = false;
			rmc.response = reply;
			rmc.error = error;

			var rmcResponseData = rmc.ToBuffer();

			QPacket np = new QPacket(p.toBuffer());
			np.flags = new List<QPacket.PACKETFLAG>() { QPacket.PACKETFLAG.FLAG_NEED_ACK, QPacket.PACKETFLAG.FLAG_RELIABLE };
			np.m_oSourceVPort = p.m_oDestinationVPort;
			np.m_oDestinationVPort = p.m_oSourceVPort;
			np.m_uiSignature = client.IDsend;
			np.usesCompression = useCompression;

			handler.MakeAndSend(client, p, np, rmcResponseData);
		}

		public static void SendRequestPacket(QPacketHandlerPRUDP handler, QPacket p, RMCPacket rmc, QClient client, RMCPRequest request, bool useCompression, uint error)
		{
			rmc.isRequest = true;
			rmc.request = request;
			rmc.error = error;
			rmc.callID = ++client.CallCounterRMC;

			var rmcRequestData = rmc.ToBuffer();

			QPacket np = new QPacket(p.toBuffer());
			np.flags = new List<QPacket.PACKETFLAG>() { QPacket.PACKETFLAG.FLAG_RELIABLE | QPacket.PACKETFLAG.FLAG_NEED_ACK };
			np.m_uiSignature = client.IDsend;
			np.usesCompression = useCompression;

			handler.MakeAndSend(client, p, np, rmcRequestData);
		}

		private static void WriteLog(QClient client, int priority, Func<string> resolve)
        {
			var unknwnClientName = client.PlayerInfo != null ? client.PlayerInfo.Name : "<unkClient>";
			QLog.WriteLine(priority, () => $"[RMC] ({unknwnClientName}) {resolve.Invoke()}"); 
		}

		private static void WriteLog(QClient client, int priority, string s)
		{
			var unknwnClientName = client.PlayerInfo != null ? client.PlayerInfo.Name : "<unkClient>";
			QLog.WriteLine(priority, $"[RMC] ({unknwnClientName}) {s}");
		}
	}
}
