package bgpdoop.hadoop.mapreduce.lib.input;


import java.io.IOException;
import java.io.InputStream;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.io.BytesWritable;
import org.apache.hadoop.io.compress.CompressionInputStream;

import p3.hadoop.common.util.BinaryUtils;
import p3.hadoop.common.util.Bytes;

public class BgpLineReader {

  private static final int DEFAULT_BUFFER_SIZE = 16384;
  private int bufferSize = DEFAULT_BUFFER_SIZE; 
  private static final int BASIC_MRT_HEADER = 12;
  private static final int MRT_HEADER_TIMESTAMP_POS=0;
  private static final int MRT_HEADER_TYPE_POS=4;
  private static final int MRT_HEADER_SUBTYPE_POS=6;
  private static final int MRT_HEADER_LEN_POS=8;
	
  private InputStream in;
  
  private byte[] buffer;
  byte[] mrt_header;
  private int bufferLength = 0;
  int consumed = 0;
  
  /**
   * Create a line reader that reads from the given stream using the 
   * given buffer-size.
   * @param in The input stream
   * @param bufferSize Size of the read buffer
   * @throws IOException
   */
  public BgpLineReader(InputStream in, int bufferSize) {
    this.in = in;
    this.bufferSize = bufferSize;
    this.buffer = new byte[this.bufferSize];
  }
 
  public BgpLineReader(InputStream in, Configuration conf) throws IOException {
	  this(in, DEFAULT_BUFFER_SIZE);//conf.getInt("io.file.buffer.size", DEFAULT_BUFFER_SIZE));
  }
  
  /**
   * Close the underlying stream.
   * @throws IOException
   */
  public void close() throws IOException {
    in.close();
  }
   
  /**
   * skip partial record
   * @return was there more data?
   * @throws IOException
   */
  int skipPartialRecord(int fraction) throws IOException {
	int pos = 0;
    return pos;
  }
  
  /**
   * Fill the buffer with more data.
   * @return was there more data?
   * @throws IOException
   */
  int readMessage(int msglen) throws IOException {
	  
	int bufferPosn = BASIC_MRT_HEADER;
	byte[] tmp_buffer = new byte[msglen];
	
    while(bufferPosn < msglen+BASIC_MRT_HEADER){
    	
		tmp_buffer = new byte[msglen-(bufferPosn-BASIC_MRT_HEADER)];	
		
    	bufferLength = in.read(tmp_buffer);    	
		if(bufferLength<0)    	return bufferPosn;
		
        System.arraycopy(tmp_buffer, 0, buffer, bufferPosn, bufferLength);
        bufferPosn += bufferLength;       
    }
    return bufferPosn;
  }
    
  long readMrtHeader(){
	  
	int headerLength = 0;
	int headerPosn = 0;
	mrt_header = new byte[BASIC_MRT_HEADER];
	  
	byte[] messageLen = new byte[4];
		
	try {
		if((headerLength = in.read(mrt_header))<BASIC_MRT_HEADER){
			headerPosn+= headerLength;			
			byte[] newheader = new byte[BASIC_MRT_HEADER-headerLength];
			
			if((headerLength = in.read(newheader))<0){
				consumed = headerPosn; 
				return -1;
			}
			System.arraycopy(newheader, 0, mrt_header, headerPosn, headerLength);
		}	
        System.arraycopy(mrt_header, 0, buffer, 0, BASIC_MRT_HEADER);
		headerPosn=0;
		
	} catch (IOException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	System.arraycopy(mrt_header, MRT_HEADER_LEN_POS, messageLen, 0, messageLen.length);	
//	BinaryUtils.printHEX(mrt_header);
//	System.out.println("<--header");
	return BinaryUtils.ubyteToLong(messageLen);
  }
  
  /**
   * Read from the InputStream into the given Text.
   * @param str the object to store the given line
   * @param maxLineLength the maximum number of bytes to store into str.
   * @param maxBytesToConsume the maximum number of bytes to consume in this call.
   * @return the number of bytes read including the newline
   * @throws IOException if the underlying stream throws
   */
	public long readLine(BytesWritable bytes, long maxLineLength,
	          long maxBytesToConsume) throws IOException {
		
		bytes.set(new BytesWritable());
		boolean hitEndOfFile = false;
		long bytesConsumed = 0;

		long msglen = readMrtHeader();
		int tmp_msglen = 0;
		
		if(msglen>Integer.MAX_VALUE)
			tmp_msglen = Integer.MAX_VALUE;
		else
			tmp_msglen = (int)msglen;
		
		if (msglen == -1)
			bytesConsumed = 0;
		else{		
			if ((bufferLength = readMessage(tmp_msglen)) < msglen+BASIC_MRT_HEADER){
				if(bufferLength<0)	return -1; // exception handling for invalid msglength
				hitEndOfFile = true;
			}
			bytesConsumed += bufferLength;
			
			if (!hitEndOfFile) {			
				bytes.set(buffer, 0, tmp_msglen+BASIC_MRT_HEADER);
				// truncate last bytes
				if(bytesConsumed<msglen)   
					bytesConsumed+=truncate((int)(msglen-bytesConsumed));
//				bytes.set(buffer, 0, BASIC_MRT_HEADER);				
			}		
		}
//		byte[] b= new byte[tmp_msglen+BASIC_MRT_HEADER];
//		System.arraycopy(buffer, 0, b, 0, b.length);
//		BinaryUtils.printHEX(b);
//		System.out.println("<--body");
//		System.out.println("bufferLen-->"+bufferLength);		
		return Math.min(bytesConsumed, Long.MAX_VALUE);	
	} 
	
	private long truncate(int len) throws IOException{
		byte[] tmp_buffer = new byte[len];
		return Math.max(in.read(tmp_buffer), len);
	}
  
	
  /**
   * Read from the InputStream into the given Text.
   * @param str the object to store the given line
   * @param maxLineLength the maximum number of bytes to store into str.
   * @return the number of bytes read including the newline
   * @throws IOException if the underlying stream throws
   */
  public long readLine(BytesWritable str, long maxLineLength) throws IOException {
    return readLine(str, maxLineLength, Long.MAX_VALUE);
  }

  /**
   * Read from the InputStream into the given Text.
   * @param str the object to store the given line
   * @return the number of bytes read including the newline
   * @throws IOException if the underlying stream throws
   */
  public long readLine(BytesWritable str) throws IOException {
    return readLine(str, Long.MAX_VALUE, Long.MAX_VALUE);
  }

}
