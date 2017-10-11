import org.datavec.api.records.reader.SequenceRecordReader;
import org.datavec.api.records.reader.impl.csv.CSVSequenceRecordReader;
import org.datavec.api.split.NumberedFileInputSplit;
import org.deeplearning4j.datasets.datavec.SequenceRecordReaderDataSetIterator;
import org.deeplearning4j.eval.Evaluation;
import org.deeplearning4j.nn.api.OptimizationAlgorithm;
import org.deeplearning4j.nn.conf.GradientNormalization;
import org.deeplearning4j.nn.conf.MultiLayerConfiguration;
import org.deeplearning4j.nn.conf.NeuralNetConfiguration;
import org.deeplearning4j.nn.conf.Updater;
import org.deeplearning4j.nn.conf.layers.GravesLSTM;
import org.deeplearning4j.nn.conf.layers.RnnOutputLayer;
import org.deeplearning4j.nn.multilayer.MultiLayerNetwork;
import org.deeplearning4j.nn.weights.WeightInit;
import org.deeplearning4j.optimize.listeners.ScoreIterationListener;
import org.nd4j.linalg.dataset.api.iterator.DataSetIterator;
import org.nd4j.linalg.lossfunctions.LossFunctions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintWriter;

public class SANN {
    private static final Logger log = LoggerFactory.getLogger(SANN.class);

    public static void main(String[] args){
        try {
            processData();

            SequenceRecordReader trainFeatures = new CSVSequenceRecordReader();
            trainFeatures.initialize(new NumberedFileInputSplit("data/%d.csv", 0, 29));
            SequenceRecordReader trainLabels = new CSVSequenceRecordReader();
            trainLabels.initialize(new NumberedFileInputSplit("label/%d.csv", 0, 29));

            DataSetIterator trainData = new SequenceRecordReaderDataSetIterator(trainFeatures, trainLabels, 1, 2,
                    false, SequenceRecordReaderDataSetIterator.AlignmentMode.ALIGN_END);

            SequenceRecordReader testFeatures = new CSVSequenceRecordReader();
            testFeatures.initialize(new NumberedFileInputSplit("data/%d.csv", 30, 39));
            SequenceRecordReader testLabels = new CSVSequenceRecordReader();
            testLabels.initialize(new NumberedFileInputSplit("label/%d.csv", 30, 39));

            DataSetIterator testData = new SequenceRecordReaderDataSetIterator(testFeatures, testLabels, 1, 2,
                    false, SequenceRecordReaderDataSetIterator.AlignmentMode.ALIGN_END);

            // ----- Configure the network -----
            MultiLayerConfiguration conf = new NeuralNetConfiguration.Builder()
                    .seed(123)    //Random number generator seed for improved repeatability. Optional.
                    .optimizationAlgo(OptimizationAlgorithm.STOCHASTIC_GRADIENT_DESCENT).iterations(1)
                    .weightInit(WeightInit.XAVIER)
                    .updater(Updater.NESTEROVS).momentum(0.9)
                    .learningRate(0.005)
                    .gradientNormalization(GradientNormalization.ClipElementWiseAbsoluteValue)
                    .gradientNormalizationThreshold(0.5)
                    .list()
                    .layer(0, new GravesLSTM.Builder().activation("tanh").nIn(95).nOut(20).build())
                    .layer(1, new RnnOutputLayer.Builder(LossFunctions.LossFunction.MCXENT)
                            .activation("softmax").nIn(20).nOut(2).build())
                    .pretrain(false).backprop(true).build();

            MultiLayerNetwork net = new MultiLayerNetwork(conf);
            net.init();

            net.setListeners(new ScoreIterationListener(20));

            // ----- Train the network, evaluating the test set performance at each epoch -----
            int nEpochs = 40;
            String str = "Test set evaluation at epoch %d: Accuracy = %.2f, F1 = %.2f";
            for (int i = 0; i < nEpochs; i++) {
                net.fit(trainData);

                //Evaluate on the test set:
                Evaluation evaluation = net.evaluate(testData);
                log.info(String.format(str, i, evaluation.accuracy(), evaluation.f1()));

                testData.reset();
                trainData.reset();
            }

        } catch(IOException | InterruptedException e){
            e.getMessage();
        }
    }

    private static void processData() throws IOException {
        BufferedReader reader = new BufferedReader(new FileReader("data/sentence.txt"));
        int csv = 0;
        PrintWriter writer = new PrintWriter("data/"+csv+".csv", "UTF-8");
        PrintWriter writerL = new PrintWriter("label/"+csv+".csv", "UTF-8");
        String line;
        boolean space = false;
        boolean start = true;
        while ((line = reader.readLine()) != null)
        {
            //for character in line, one hot encode to csv
            for (char c : line.toCharArray()) {
                if (c < 32 || c > 126){
                    continue;
                }

                int i;
                c -= 32;
                for (i = 0; i < c; i++ ){
                    if (i == 0){
                        writer.print("0");
                    } else {
                        writer.print(",0");
                    }
                }
                if (i == 0){
                    writer.print("1");
                } else {
                    writer.print(",1");
                }
                for (int j = c+1; j <= 94; j++) {
                    writer.print(",0");
                }
                writer.print("\n");

                //add label as needed
                if (c == 0) space = true;
                if (c != 0 && space || start){
                    writerL.println("1");
                    space = false;
                } else {
                    writerL.println("0");
                }
                start = false;
            }

            //at blank line, start new csv
            if (line.equals("")){
                //System.out.println("here");
                writer.close();
                writerL.close();
                csv += 1;
                writer = new PrintWriter("data/"+csv+".csv", "UTF-8");
                writerL = new PrintWriter("label/"+csv+".csv", "UTF-8");
            }
        }
        reader.close();
    }
}
