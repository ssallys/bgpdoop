package bgpdoop.hadoop.mapreduce.lib.input;

import java.io.IOException;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.BytesWritable;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.io.compress.CompressionCodec;
import org.apache.hadoop.io.compress.CompressionCodecFactory;
import org.apache.hadoop.mapreduce.InputSplit;
import org.apache.hadoop.mapreduce.RecordReader;
import org.apache.hadoop.mapreduce.TaskAttemptContext;
import org.apache.hadoop.mapreduce.lib.input.FileSplit;
import org.apache.hadoop.mapreduce.lib.input.LineRecordReader;
import org.apache.hadoop.util.LineReader;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.logging.Log;

/**
 * Treats keys as offset in file and value as line. 
 */
public class BgpVlenRecordReader extends RecordReader<LongWritable,BytesWritable>{
//  private static final Log LOG = LogFactory.getLog(LineRecordReader.class.getName());

  private static final Log LOG = LogFactory.getLog(BgpVlenRecordReader.class.getName());
  
  private CompressionCodecFactory compressionCodecs = null;
  private long start;
  private long pos;
  private long end;
  private BgpLineReader in;
  private long maxLineLength;
  private LongWritable key = null;
  private BytesWritable value = null;
  private String filename = null;

  public void initialize(InputSplit genericSplit,
          TaskAttemptContext context)  {
	  
	    FileSplit split = (FileSplit) genericSplit;
	    filename = split.getPath().toString();
	    Configuration job = context.getConfiguration();  
	  
	    this.maxLineLength = job.getLong("mapred.linerecordreader.maxlength",Integer.MAX_VALUE);
	    
	    start = split.getStart();
		end = start + split.getLength();
		final Path file = split.getPath();		
	    compressionCodecs = new CompressionCodecFactory(job);
	    final CompressionCodec codec = compressionCodecs.getCodec(file);	
		
		// open the file and seek to the start of the split
		FileSystem fs;
		FSDataInputStream fileIn=null;
		try {
			fs = file.getFileSystem(job);
			fileIn = fs.open(split.getPath());
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

	    boolean skipPartialRecord = false;	
	    int fraction = 4000;
	    
	    if (codec != null) {
	      try {
			in = new BgpLineReader(codec.createInputStream(fileIn), job);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	      end = Long.MAX_VALUE;
	      
	    } else {
	      if (start != 0) {
	    	  skipPartialRecord = true;
	    	  try {
				fileIn.seek(start);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
	      }
	      try {
				in = new BgpLineReader(fileIn, job);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
	    }
	    this.pos = start;
		System.out.println("input split path ==> "+filename);
    }

    /**
     * Read raw bytes from a PcapFile.
     */
	public boolean nextKeyValue() throws IOException {
    	
		if (key == null) {
			key = new LongWritable();
		}
		key.set(pos);
		
        if(value == null){
        	value = new BytesWritable();
        }
        
		long newSize = 0;
//		pos = end;
        while (pos < end) {
        	newSize = in.readLine(value, maxLineLength, Math.max(Math.min(Long.MAX_VALUE, end-pos),
        			Long.MAX_VALUE));
          
          if (newSize == 0) break;
          if (newSize <  0){
//        	  if(newSize == -100)
        		  System.out.println("Error: input split path ==> "+filename);
        	  break;
          }

          pos += newSize;
//          if(cnt++==50000) pos=end;
          
          if (newSize < maxLineLength) break;
          
		  // line too long. try again
		  LOG.info("Skipped line of size " + newSize + " at pos " + 
		           (pos - newSize));
        }
		if (newSize < 1) {
			  key = null;
			  value = null;
			  return false;
		} else {
			  return true;
		} 
    }
	int cnt = 0;
	  
	@Override
	public LongWritable getCurrentKey() throws IOException,
			InterruptedException {
		// TODO Auto-generated method stub
		return key;
	}
	
	
	@Override
	public BytesWritable getCurrentValue() throws IOException,
			InterruptedException {
		// TODO Auto-generated method stub
		return value;
	}

	/**
	* Get the progress within the split
	*/
	@Override
	  public float getProgress() {
	    if (start == end) {
	      return 0.0f;
	    } else {
	      return Math.min(1.0f, (pos - start) / (float)(end - start));
	    }
	  }
	  
	  public synchronized void close() throws IOException {
	    if (in != null) {
	      in.close(); 
	    }
	  }
	}