package bgpdoop.analyzer.lib;

import java.net.InetAddress;
import java.net.UnknownHostException;

import p3.hadoop.common.util.BinaryUtils;
import p3.hadoop.common.util.EZBytes;

public class Bgp4mp_State {

	/* BGP state - defined in RFC1771 */
	public static final int BGP_STATE_IDLE			= 1;
	public static final int BGP_STATE_CONNECT		= 2;
	public static final int BGP_STATE_ACTIVE		= 3;
	public static final int BGP_STATE_OPENSENT		= 4;
	public static final int BGP_STATE_OPENCONFIRM	= 5;
	public static final int BGP_STATE_ESTABLISHED	= 6;

	/* BGP3MP_STATE_CHANGE & BGP3MP_STATE_CHANGE_AS4*/
	public long		peer_as;
	public long		local_as;
	public int		interface_index;
	public int		address_family;
	public String	peer_ip;
	public String	local_ip;
	public int	old_state;
	public int	new_state;
		
	public boolean parseStateChange(byte[] pdata) throws UnknownHostException{	
		
		EZBytes eb = new EZBytes(pdata.length);
		eb.PutBytes(pdata, 0, pdata.length);
		int pos = 0;
		
		peer_as = BinaryUtils.ubyteToLong(eb.GetBytes(pos, 2)); pos+=2;
		local_as = BinaryUtils.ubyteToLong(eb.GetBytes(pos, 2)); pos+=2;
		interface_index = BinaryUtils.byteToInt(eb.GetBytes(pos, 2)); pos+=2;
		address_family = BinaryUtils.byteToInt(eb.GetBytes(pos, 2)); pos+=2;
		
		if(address_family==1){ // ipv4
			peer_ip = InetAddress.getByAddress(eb.GetBytes(pos, 4)).toString(); pos+=4;
			local_ip = InetAddress.getByAddress(eb.GetBytes(pos, 4)).toString(); pos+=4;
		}else{
			peer_ip = InetAddress.getByAddress(eb.GetBytes(pos, 16)).toString(); pos+=16;
			local_ip = InetAddress.getByAddress(eb.GetBytes(pos, 16)).toString(); pos+=16;
		}	
		old_state = BinaryUtils.byteToInt(eb.GetBytes(pos, 2)); pos+=2;	
		new_state = BinaryUtils.byteToInt(eb.GetBytes(pos, 2)); pos+=2;	
		
	    return true;    
	}
	
	public boolean parseStateChange4(byte[] pdata) throws UnknownHostException{	
		
		EZBytes eb = new EZBytes(pdata.length);
		eb.PutBytes(pdata, 0, pdata.length);
		int pos = 0;
		
		peer_as = BinaryUtils.ubyteToLong(eb.GetBytes(pos, 4)); pos+=4;
		local_as = BinaryUtils.ubyteToLong(eb.GetBytes(pos, 4)); pos+=4;
		interface_index = BinaryUtils.byteToInt(eb.GetBytes(pos, 2)); pos+=2;
		address_family = BinaryUtils.byteToInt(eb.GetBytes(pos, 2)); pos+=2;
		
		if(address_family==1){ // ipv4
			peer_ip = InetAddress.getByAddress(eb.GetBytes(pos, 4)).toString(); pos+=4;
			local_ip = InetAddress.getByAddress(eb.GetBytes(pos, 4)).toString(); pos+=4;
		}else{
			peer_ip = InetAddress.getByAddress(eb.GetBytes(pos, 16)).toString(); pos+=16;
			local_ip = InetAddress.getByAddress(eb.GetBytes(pos, 16)).toString(); pos+=16;
		}	
		old_state = BinaryUtils.byteToInt(eb.GetBytes(pos, 2)); pos+=2;	
		new_state = BinaryUtils.byteToInt(eb.GetBytes(pos, 2)); pos+=2;	
		
	    return true;    
	}
	
	
	public String toString(){
		StringBuilder sb = new StringBuilder();
		sb
		.append(peer_as).append("|")
		.append(local_as).append("|")
		.append(interface_index).append("|")
		.append(address_family).append("|")
		.append(peer_ip).append("|")
		.append(local_ip).append("|")
		.append(old_state).append("|")
		.append(new_state);		
		return sb.toString();
	}
}

