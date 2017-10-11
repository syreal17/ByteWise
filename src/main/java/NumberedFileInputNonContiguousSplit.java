import org.datavec.api.split.InputSplit;
import org.datavec.api.split.NumberedFileInputSplit;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Paths;
import java.util.Iterator;


public class NumberedFileInputNonContiguousSplit implements InputSplit {
    private final String baseString;
    private final int minIdx1;
    private final int maxIdx1;
    private final int minIdx2;
    private final int maxIdx2;

    public NumberedFileInputNonContiguousSplit(String baseString, int minIdxInclusive, int maxIdxInclusive, int minIdxInclusive2, int maxIdxInclusive2) {
        if(baseString != null && baseString.contains("%d")) {
            this.baseString = baseString;
            this.minIdx1 = minIdxInclusive;
            this.maxIdx1 = maxIdxInclusive;
            this.minIdx2 = minIdxInclusive2;
            this.maxIdx2 = maxIdxInclusive2;
        } else {
            throw new IllegalArgumentException("Base String must contain  character sequence %d");
        }
    }

    public NumberedFileInputNonContiguousSplit(String baseString, int minIdxInclusive, int maxIdxInclusive) {
        if(baseString != null && baseString.contains("%d")) {
            this.baseString = baseString;
            this.minIdx1 = minIdxInclusive;
            this.maxIdx1 = maxIdxInclusive;
            this.minIdx2 = -1;
            this.maxIdx2 = -1;
        } else {
            throw new IllegalArgumentException("Base String must contain  character sequence %d");
        }
    }

    public long length() {
        int length = 0;
        if (this.maxIdx1 != -1 && this.minIdx1 != -1){
            length += (this.maxIdx1 - this.minIdx1 + 1);
        }

        if (this.maxIdx2 != -1 && this.minIdx2 != -1){
            length += (this.maxIdx2 - this.minIdx2 + 1);
        }

        return (long)length;
    }

    public URI[] locations() {
        URI[] uris = new URI[(int)this.length()];
        int x = 0;

        if( this.minIdx1 != -1 && this.maxIdx1 != -1) {
            for (int i = this.minIdx1; i <= this.maxIdx1; ++i) {
                uris[x++] = Paths.get(String.format(this.baseString, new Object[]{Integer.valueOf(i)}), new String[0]).toUri();
            }
        }

        if( this.maxIdx2 != -1 && this.minIdx2 != -1) {
            for (int i = this.minIdx2; i <= this.maxIdx2; ++i) {
                uris[x++] = Paths.get(String.format(this.baseString, new Object[]{Integer.valueOf(i)}), new String[0]).toUri();
            }
        }

        return uris;
    }

    public void write(DataOutput out) throws IOException {
    }

    public void readFields(DataInput in) throws IOException {
    }

    public double toDouble() {
        throw new UnsupportedOperationException();
    }

    public float toFloat() {
        throw new UnsupportedOperationException();
    }

    public int toInt() {
        throw new UnsupportedOperationException();
    }

    public long toLong() {
        throw new UnsupportedOperationException();
    }

    public Iterator<URI> locationsIterator() { throw new UnsupportedOperationException(); };

    public Iterator<String> locationsPathIterator() { throw new UnsupportedOperationException();};

    public void reset() { throw new UnsupportedOperationException(); };
}
