using System.IO;
using System.Text;

namespace QNetZ
{
	/// <summary>
	/// Quazal string-based RMC packet format used by Watch Dogs 1 / QRV protocol.
	/// Unlike Nintendo NEX (numeric protocol IDs), QRV uses null-terminated ASCII
	/// strings for protocol and method names.
	///
	/// Request layout:
	///   [U32] payload_size
	///   [U16] protocol_name_len (including null)
	///   [chars] protocol_name\0
	///   [U8]  type: 1 = request
	///   [U32] call_id
	///   [U16] method_name_len (including null, "Protocol::Method" form)
	///   [chars] method_name\0
	///   [bytes] parameter data
	///
	/// Response layout:
	///   [U32] payload_size
	///   [U16] protocol_name_len (including null)
	///   [chars] protocol_name\0
	///   [U8]  type: 2 = response
	///   [U8]  success: 1 = success, 0 = failure
	///   [U32] call_id
	///   [bytes] return data
	/// </summary>
	public class QRVPacket
	{
		public string ProtocolName;
		public bool IsRequest;
		public uint CallID;
		public string MethodName;
		public byte[] ParameterData;

		public QRVPacket(byte[] payload)
		{
			var m = new MemoryStream(payload);
			Helper.ReadU32(m); // payload_size prefix — skip

			ushort protoLen = Helper.ReadU16(m);
			var protoBytes = new byte[protoLen];
			m.Read(protoBytes, 0, protoLen);
			ProtocolName = Encoding.ASCII.GetString(protoBytes).TrimEnd('\0');

			IsRequest = Helper.ReadU8(m) == 1;
			CallID = Helper.ReadU32(m);

			ushort methodLen = Helper.ReadU16(m);
			var methodBytes = new byte[methodLen];
			m.Read(methodBytes, 0, methodLen);
			MethodName = Encoding.ASCII.GetString(methodBytes).TrimEnd('\0');

			int remaining = (int)(m.Length - m.Position);
			ParameterData = new byte[remaining];
			if (remaining > 0)
				m.Read(ParameterData, 0, remaining);
		}

		/// <summary>
		/// Returns true if the PRUDP payload uses the QRV string-based RMC format.
		/// Detection: bytes 4-5 are a U16 string length with high byte 0x00 and
		/// value > 1, which distinguishes it from NEX's protocol-ID byte.
		/// </summary>
		public static bool IsQRVFormat(byte[] payload)
		{
			return payload.Length > 5
				&& (payload[4] & 0x80) == 0  // not a NEX request (bit 7 clear)
				&& payload[5] == 0x00          // high byte of U16 string length
				&& payload[4] > 1;             // length > 1 (any real protocol name)
		}

		public byte[] MakeSuccessResponse(byte[] data = null)
		{
			var body = new MemoryStream();

			var protoBytes = Encoding.ASCII.GetBytes(ProtocolName + "\0");
			Helper.WriteU16(body, (ushort)protoBytes.Length);
			body.Write(protoBytes, 0, protoBytes.Length);

			Helper.WriteU8(body, 0); // type = 0 (response, matching real Quazal server)
			Helper.WriteU8(body, 1); // success
			Helper.WriteU32(body, CallID);

			// Real server includes method name (with * suffix) in response
			var methodBytes = Encoding.ASCII.GetBytes(MethodName + "*\0");
			Helper.WriteU16(body, (ushort)methodBytes.Length);
			body.Write(methodBytes, 0, methodBytes.Length);

			if (data != null && data.Length > 0)
				body.Write(data, 0, data.Length);

			var bodyBytes = body.ToArray();
			var result = new MemoryStream();
			Helper.WriteU32(result, (uint)bodyBytes.Length);
			result.Write(bodyBytes, 0, bodyBytes.Length);
			return result.ToArray();
		}

		public byte[] MakeErrorResponse(uint errorCode)
		{
			var body = new MemoryStream();

			var protoBytes = Encoding.ASCII.GetBytes(ProtocolName + "\0");
			Helper.WriteU16(body, (ushort)protoBytes.Length);
			body.Write(protoBytes, 0, protoBytes.Length);

			Helper.WriteU8(body, 2); // type = response
			Helper.WriteU8(body, 0); // failure
			Helper.WriteU32(body, errorCode | 0x80000000);
			Helper.WriteU32(body, CallID);

			var bodyBytes = body.ToArray();
			var result = new MemoryStream();
			Helper.WriteU32(result, (uint)bodyBytes.Length);
			result.Write(bodyBytes, 0, bodyBytes.Length);
			return result.ToArray();
		}

		public override string ToString()
		{
			return $"[CallID={CallID} {MethodName}]";
		}
	}
}
