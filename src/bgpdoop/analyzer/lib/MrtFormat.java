package bgpdoop.analyzer.lib;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import org.apache.hadoop.record.Buffer;

import p3.hadoop.common.util.BinaryUtils;
import p3.hadoop.common.util.Bytes;
import p3.hadoop.common.util.EZBytes;


/** This class represents TCP packet. */
public class MrtFormat 
{
	
	public static final int BGPDUMP_TYPE_MRTD_TABLE_DUMP						= 12;
	public static final int BGPDUMP_SUBTYPE_MRTD_TABLE_DUMP_AFI_IP				= 1;
	public static final int BGPDUMP_SUBTYPE_MRTD_TABLE_DUMP_AFI_IP6				= 2;
	public static final int BGPDUMP_SUBTYPE_MRTD_TABLE_DUMP_AFI_IP_32BIT_AS		= 3;
	public static final int BGPDUMP_SUBTYPE_MRTD_TABLE_DUMP_AFI_IP6_32BIT_AS	= 4;
	
	/* TABLE_DUMP_V2 types */
	public static final int BGPDUMP_TYPE_TABLE_DUMP_V2                      = 13;
	public static final int BGPDUMP_SUBTYPE_TABLE_DUMP_V2_PEER_INDEX_TABLE  = 1;
	public static final int BGPDUMP_SUBTYPE_TABLE_DUMP_V2_RIB_IPV4_UNICAST  = 2;
	public static final int BGPDUMP_SUBTYPE_TABLE_DUMP_V2_RIB_IPV4_MULTICAST= 3;
	public static final int BGPDUMP_SUBTYPE_TABLE_DUMP_V2_RIB_IPV6_UNICAST  = 4;
	public static final int BGPDUMP_SUBTYPE_TABLE_DUMP_V2_RIB_IPV6_MULTICAST= 5;
	public static final int BGPDUMP_SUBTYPE_TABLE_DUMP_V2_RIB_GENERIC       = 6;
	
	public static final int BGPDUMP_PEERTYPE_TABLE_DUMP_V2_AFI_IP           = 0;
	public static final int BGPDUMP_PEERTYPE_TABLE_DUMP_V2_AFI_IP6          = 1;
	public static final int BGPDUMP_PEERTYPE_TABLE_DUMP_V2_AS2              = 0;
	public static final int BGPDUMP_PEERTYPE_TABLE_DUMP_V2_AS4              = 2;
	public static final int BGPDUMP_TYPE_TABLE_DUMP_V2_MAX_VIEWNAME_LEN     = 255;

	/* BGP4MP types */
	public static final int BGPDUMP_TYPE_BGP4MP			        	= 16; 	/* MSG_PROTOCOL_BGP4MP */
	public static final int BGPDUMP_SUBTYPE_BGP4MP_STATE_CHANGE		= 0;  	/* BGP4MP_STATE_CHANGE */
	public static final int BGPDUMP_SUBTYPE_BGP4MP_MESSAGE			= 1;  	/* BGP4MP_MESSAGE */
	public static final int BGPDUMP_SUBTYPE_BGP4MP_ENTRY			= 2;  	/* BGP4MP_ENTRY */
	public static final int BGPDUMP_SUBTYPE_BGP4MP_SNAPSHOT			= 3;  	/* BGP4MP_SNAPSHOT */
	public static final int BGPDUMP_SUBTYPE_BGP4MP_MESSAGE_AS4		= 4;  	/* BGP4MP_MESSAGE_AS4 */
	public static final int BGPDUMP_SUBTYPE_BGP4MP_STATE_CHANGE_AS4	= 5;/* BGP4MP_STATE_CHANGE_AS4 */
		
	private int pos;
	private EZBytes eb;
	
	public long timestamp;
	public int type;
	public int subtype;
	public long length;
				
	public int parseMrtHeader(byte[] pdata){	
		EZBytes eb = new EZBytes(pdata.length);
		eb.PutBytes(pdata, 0, pdata.length);
		
		// ...| time_sec | time_usec
		this.timestamp = BinaryUtils.ubyteToLong(eb.GetBytes(pos, 4)); pos+=4;
		this.type = BinaryUtils.byteToInt(eb.GetBytes(pos,2));	pos+=2;
		this.subtype = BinaryUtils.byteToInt(eb.GetBytes(pos,2)); pos+=2;
		this.length = BinaryUtils.ubyteToLong(eb.GetBytes(pos,4)); pos+=4;
		
	    return pos;
	}
}