import org.datavec.api.records.reader.SequenceRecordReader;
import org.datavec.api.records.reader.impl.csv.CSVSequenceRecordReader;
import org.datavec.api.split.NumberedFileInputSplit;
import org.deeplearning4j.datasets.datavec.SequenceRecordReaderDataSetIterator;
import org.deeplearning4j.datasets.iterator.AsyncDataSetIterator;
import org.deeplearning4j.eval.Evaluation;
import org.deeplearning4j.nn.api.OptimizationAlgorithm;
import org.deeplearning4j.nn.conf.*;
import org.deeplearning4j.nn.conf.layers.GravesBidirectionalLSTM;
import org.deeplearning4j.nn.conf.layers.RnnOutputLayer;
import org.deeplearning4j.nn.multilayer.MultiLayerNetwork;
import org.deeplearning4j.nn.weights.WeightInit;
import org.deeplearning4j.optimize.listeners.PerformanceListener;
import org.deeplearning4j.optimize.listeners.ScoreIterationListener;
import org.deeplearning4j.util.ModelSerializer;
import org.nd4j.linalg.activations.Activation;
import org.nd4j.linalg.api.ndarray.INDArray;
import org.nd4j.linalg.dataset.DataSet;
import org.nd4j.linalg.dataset.ExistingMiniBatchDataSetIterator;
import org.nd4j.linalg.dataset.api.iterator.DataSetIterator;
import org.nd4j.linalg.lossfunctions.LossFunctions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;

public class ByteWise {
    private static final Logger log = LoggerFactory.getLogger(ByteWise.class);
    private static final int NUM_LABELS = 2;
    private static final int NUM_EPOCHS = 6;
    private static final int K = 5;
    private static final int MINIBATCH_SIZE = 32;
    private static final String SAVED_NET_PREFIX = "ByteWise-BCF-New-";
    private static final String FEATURES_FOLDER = "data/Binary/neuralnet_data/mono-diversity/features/";
    private static final String LABELS_FOLDER = "data/Binary/neuralnet_data/mono-diversity/labels/";
    private static final String DATA_NAME = "%d.csv";
    private static final String PRESAVE_TRAIN_FOLDER = "data/Binary/presave_data/mono-diversity/train-%d-data/";
    private static final String PRESAVE_TEST_FOLDER = "data/Binary/presave_data/mono-diversity/test-%d-data/";
    private static final String PRESAVE_TRAIN_PREFIX = "mb" + MINIBATCH_SIZE + "-train-";
    private static final String PRESAVE_TEST_PREFIX = "mb" + MINIBATCH_SIZE + "-test-";
    private static final String PRESAVE_EXT = ".bin";
    private static final String PREDICTIONS_FOLDER = "predictions/";
    private static final int START_DATASET_I = 0;
    private static final int END_DATASET_I = 10554;
    private static final String TEST_NETWORK = "NNs/multidiversity-2lbl-BCF-mal-bidirectional/BW-BCF-24hr-0.zip";

    //sy: in practice, we've only had one of the following calls uncommented at a time:
    public static void main(String[] args){

        //sy: presaving is for increasing the speed of training, but it takes quite a while
        //--------------------------------------------------------------------------------------------------------------
//        try {
//            presave_kfold_data(
//                K,
//                START_DATASET_I,
//                END_DATASET_I,
//                MINIBATCH_SIZE,
//                NUM_LABELS,
//                DATA_NAME,
//                FEATURES_FOLDER,
//                LABELS_FOLDER,
//                PRESAVE_TRAIN_FOLDER,
//                PRESAVE_TEST_FOLDER,
//                PRESAVE_TRAIN_PREFIX,
//                PRESAVE_TEST_PREFIX,
//                PRESAVE_EXT
//            );
//        } catch (Exception e) {
//            System.out.println(e.getMessage());
//        }
        //--------------------------------------------------------------------------------------------------------------

        //sy: trains new networks based on presave data
        //--------------------------------------------------------------------------------------------------------------
//        kfold_train_new_networks_on_presaved(
//                K,
//                START_DATASET_I,
//                END_DATASET_I,
//                NUM_EPOCHS,
//                NUM_LABELS,
//                PRESAVE_TRAIN_FOLDER,
//                PRESAVE_TEST_FOLDER,
//                PRESAVE_TRAIN_PREFIX,
//                PRESAVE_TEST_PREFIX,
//                PRESAVE_EXT,
//                SAVED_NET_PREFIX
//        );
        //--------------------------------------------------------------------------------------------------------------

        //sy: trains new networks based on the features and labels in folders specified in constants
        //--------------------------------------------------------------------------------------------------------------
        kfold_train_new_networks(
            K,
            START_DATASET_I,
            END_DATASET_I,
            MINIBATCH_SIZE,
            NUM_EPOCHS,
            NUM_LABELS,
            FEATURES_FOLDER,
            LABELS_FOLDER,
            DATA_NAME,
            SAVED_NET_PREFIX
        );
        //--------------------------------------------------------------------------------------------------------------

        //sy: load a saved network and run it on a range of csvs, from START_TEST_I to END_TEST_I for 3 label data
        //--------------------------------------------------------------------------------------------------------------
//        for( int i = START_DATASET_I; i <= END_DATASET_I; i++){
//            load_and_run_network_3lbl(
//                TEST_NETWORK,
//                FEATURES_FOLDER,
//                LABELS_FOLDER,
//                DATA_NAME,
//                PREDICTIONS_FOLDER,
//                i
//            );
//        }
        //--------------------------------------------------------------------------------------------------------------

        //sy: load a saved network and run it on a range of csvs, from START_TEST_I to END_TEST_I for 2 label data
        //--------------------------------------------------------------------------------------------------------------
//        for( int i = START_DATASET_I; i <=END_DATASET_I; i++) {
//            load_and_run_network_2lbl(
//                TEST_NETWORK,
//                FEATURES_FOLDER,
//                LABELS_FOLDER,
//                DATA_NAME,
//                PREDICTIONS_FOLDER,
//                i
//            );
//        }
        //--------------------------------------------------------------------------------------------------------------

        //sy: still WIP. Towards saving network info to analyze with LSTMVis
        //--------------------------------------------------------------------------------------------------------------
//        load_and_step_network(
//            NUM_LABELS,
//            TEST_NETWORK,
//            FEATURES_FOLDER,
//            LABELS_FOLDER,
//            DATA_NAME,
//            1
//        );
        //--------------------------------------------------------------------------------------------------------------
    }

    private static MultiLayerConfiguration getByteWiseConfiguration(int nLabels)
    {
        // ----- Configure the network -----
        MultiLayerConfiguration conf = new NeuralNetConfiguration.Builder()
                //.seed(123)    //Random number generator seed for improved repeatability. Optional.
                .optimizationAlgo(OptimizationAlgorithm.STOCHASTIC_GRADIENT_DESCENT).iterations(1)
                .weightInit(WeightInit.XAVIER)
                .updater(Updater.RMSPROP)
                .learningRate(0.1)
                .list()
                .layer(0, new GravesBidirectionalLSTM.Builder().activation(Activation.TANH).nIn(256).nOut(16).build())
                .layer(1, new RnnOutputLayer.Builder(LossFunctions.LossFunction.NEGATIVELOGLIKELIHOOD)
                        .activation(Activation.SOFTMAX).nIn(16).nOut(nLabels).build())
                .pretrain(false).backprop(true).build();
        return conf;
    }

    public static void presave_kfold_data(
            int k,
            int ds_min,
            int ds_max,
            int mbSize,
            int nLabels,
            String dataName,
            String dataFolder,
            String labelsFolder,
            String nth_train_kfold_folder,
            String nth_test_kfold_folder,
            String presaveTrainPrefix,
            String presaveTestPrefix,
            String presaveExt
    ) throws Exception
    {
        int ds_size = ds_max - ds_min + 1;
        if (ds_size % k != 0){
            throw new Exception("Data set not divisible by k");
        }
        int kfold_size = ds_size / k;
        int test_lidx = 0;
        int test_ridx = 0;
        int ltrain_lidx = -1;
        int ltrain_ridx = -1;
        int rtrain_lidx = -1;
        int rtrain_ridx = -1;

        for (int i = 0; i < k; i++) {

            // ----- Configure the data (k-fold cross validation) -----
            test_lidx = i * kfold_size;
            test_ridx = test_lidx + kfold_size - 1;

            if (test_lidx - 1 < ds_min) {
                ltrain_lidx = -1;
                ltrain_ridx = -1;
            } else {
                ltrain_lidx = ds_min;
                ltrain_ridx = test_lidx - 1;
            }

            if (test_ridx + 1 > ds_max) {
                rtrain_lidx = -1;
                rtrain_ridx = -1;
            } else {
                rtrain_lidx = test_ridx + 1;
                rtrain_ridx = ds_max;
            }

            SequenceRecordReader testFeatures = new CSVSequenceRecordReader();
            testFeatures.initialize(new NumberedFileInputSplit(
                    dataFolder + dataName, test_lidx, test_ridx));
            SequenceRecordReader testLabels = new CSVSequenceRecordReader();
            testLabels.initialize(new NumberedFileInputSplit(
                    labelsFolder + dataName, test_lidx, test_ridx));

            DataSetIterator testData = new SequenceRecordReaderDataSetIterator(testFeatures, testLabels, mbSize, nLabels,
                    false, SequenceRecordReaderDataSetIterator.AlignmentMode.ALIGN_END);

            SequenceRecordReader trainFeatures = new CSVSequenceRecordReader();
            trainFeatures.initialize(new NumberedFileInputNonContiguousSplit(
                    dataFolder + dataName, ltrain_lidx, ltrain_ridx, rtrain_lidx, rtrain_ridx));
            SequenceRecordReader trainLabels = new CSVSequenceRecordReader();
            trainLabels.initialize(new NumberedFileInputNonContiguousSplit(
                    labelsFolder + dataName, ltrain_lidx, ltrain_ridx, rtrain_lidx, rtrain_ridx));

            DataSetIterator trainData = new SequenceRecordReaderDataSetIterator(trainFeatures, trainLabels, mbSize, nLabels,
                    false, SequenceRecordReaderDataSetIterator.AlignmentMode.ALIGN_END);

            File trainFolder = new File(String.format(nth_train_kfold_folder, i));
            trainFolder.mkdirs();

            File testFolder = new File(String.format(nth_test_kfold_folder, i));
            testFolder.mkdirs();

            int trainDataSaved = 0;
            int testDataSaved = 0;
            while(trainData.hasNext()) {
                trainData.next().save(new File(trainFolder,presaveTrainPrefix+ trainDataSaved + presaveExt));
                trainDataSaved++;
            }

            while(testData.hasNext()) {
                testData.next().save(new File(testFolder,presaveTestPrefix + testDataSaved + presaveExt));
                testDataSaved++;
            }
        }
    }

    public static void kfold_train_new_networks_on_presaved(
            int k,
            int ds_min,
            int ds_max,
            int nEpochs,
            int nLabels,
            String nthTrainKfoldFolder,
            String nthTestKfoldFolder,
            String presaveTrainPrefix,
            String presaveTestPrefix,
            String presaveExt,
            String savedNetPrefix
    )
    {
        try {

            // ----- Configure the network -----
            MultiLayerConfiguration conf = getByteWiseConfiguration(nLabels);

            int ds_size = ds_max - ds_min + 1;
            if (ds_size % k != 0){
                throw new Exception("Data set not divisible by k");
            }

            String[] results = new String[k];
            // ----- Train the network, evaluating the test set performance at each epoch -----
            String str = "Test set evaluation at kfold %d, epoch %d: Accuracy = %.2f, F1 = %.2f, R = %.2f, P = %.2f";
            for (int i = 0; i < k; i++) {
                MultiLayerNetwork net = new MultiLayerNetwork(conf);
                net.init();
                //net.setListeners(new ScoreIterationListener(20));
                net.setListeners(new PerformanceListener(20));

                // ----- Configure the data (k-fold cross validation) -----
                DataSetIterator existingTrainingData = new ExistingMiniBatchDataSetIterator(
                        new File(String.format(nthTrainKfoldFolder, i)), presaveTrainPrefix+"%d"+presaveExt);
                DataSetIterator asyncTrain = new AsyncDataSetIterator(existingTrainingData);

                DataSetIterator existingTestData = new ExistingMiniBatchDataSetIterator(
                        new File(String.format(nthTestKfoldFolder, i)),presaveTestPrefix+"%d"+presaveExt);
                DataSetIterator asyncTest = new AsyncDataSetIterator(existingTestData);

                System.out.println("----------------------------------------");

                for (int j = 0; j < nEpochs; j++) {
                    System.out.println("Epoch: " + j + "; K-Fold: " + i);
                    net.fit(asyncTrain);

                    //Evaluate on the test set:
                    Evaluation evaluation = net.evaluate(asyncTest);
                    log.info(String.format(str, i, j, evaluation.accuracy(), evaluation.f1(), evaluation.recall(), evaluation.precision()));
                    results[i] = String.format(str, i, j, evaluation.accuracy(), evaluation.f1(), evaluation.recall(), evaluation.precision());

                    asyncTest.reset();
                    asyncTrain.reset();
                }

                //save the nn so we can analyze it later
                File locationToSave = new File(savedNetPrefix + i + ".zip");
                boolean saveUpdater = true;
                ModelSerializer.writeModel(net, locationToSave, saveUpdater);
            }

            for( String result: results ){
                System.out.println(result);
            }

        } catch(IOException | InterruptedException e) {
            System.out.println("IOEXception");
            System.out.println(e.getMessage());
        } catch(Exception e) {
            System.out.println("Exception e");
            System.out.println(e.getMessage());
        }
    }

    public static void kfold_train_new_networks(
            int k,
            int ds_min,
            int ds_max,
            int mbSize,
            int nEpochs,
            int nLabels,
            String featuresFolder,
            String labelsFolder,
            String dataName,
            String savedNetPrefix
    )
    {
        try {
            MultiLayerConfiguration conf = getByteWiseConfiguration(nLabels);

            int ds_size = ds_max - ds_min + 1;
            if (ds_size % k != 0){
                throw new Exception("Data set not divisible by k");
            }
            int kfold_size = ds_size / k;
            int test_lidx = 0;
            int test_ridx = 0;
            int ltrain_lidx = -1;
            int ltrain_ridx = -1;
            int rtrain_lidx = -1;
            int rtrain_ridx = -1;
            String[] results = new String[k];
            // ----- Train the network, evaluating the test set performance at each epoch -----
            String str = "Test set evaluation at kfold %d, epoch %d: Accuracy = %.2f, F1 = %.2f, R = %.2f, P = %.2f";

            for (int i = 0; i < k; i++) {
                MultiLayerNetwork net = new MultiLayerNetwork(conf);
                net.init();
                net.setListeners(new ScoreIterationListener(20));
                //net.setListeners(new PerformanceListener(20));

                // ----- Configure the data (k-fold cross validation) -----
                test_lidx = i * kfold_size;
                test_ridx = test_lidx + kfold_size - 1;

                if (test_lidx - 1 < ds_min) {
                    ltrain_lidx = -1;
                    ltrain_ridx = -1;
                } else {
                    ltrain_lidx = ds_min;
                    ltrain_ridx = test_lidx - 1;
                }

                if (test_ridx + 1 > ds_max) {
                    rtrain_lidx = -1;
                    rtrain_ridx = -1;
                } else {
                    rtrain_lidx = test_ridx + 1;
                    rtrain_ridx = ds_max;
                }

                SequenceRecordReader testFeatures = new CSVSequenceRecordReader();
                testFeatures.initialize(new NumberedFileInputSplit(
                        featuresFolder+dataName, test_lidx, test_ridx));
                SequenceRecordReader testLabels = new CSVSequenceRecordReader();
                testLabels.initialize(new NumberedFileInputSplit(
                        labelsFolder+dataName, test_lidx, test_ridx));

                DataSetIterator testData = new SequenceRecordReaderDataSetIterator(testFeatures, testLabels, mbSize, nLabels,
                        false, SequenceRecordReaderDataSetIterator.AlignmentMode.ALIGN_END);

                SequenceRecordReader trainFeatures = new CSVSequenceRecordReader();
                trainFeatures.initialize(new NumberedFileInputNonContiguousSplit(
                        featuresFolder+dataName, ltrain_lidx, ltrain_ridx, rtrain_lidx, rtrain_ridx));
                SequenceRecordReader trainLabels = new CSVSequenceRecordReader();
                trainLabels.initialize(new NumberedFileInputNonContiguousSplit(
                        labelsFolder+dataName, ltrain_lidx, ltrain_ridx, rtrain_lidx, rtrain_ridx));

                DataSetIterator trainData = new SequenceRecordReaderDataSetIterator(trainFeatures, trainLabels, mbSize, nLabels,
                        false, SequenceRecordReaderDataSetIterator.AlignmentMode.ALIGN_END);

                System.out.println("Indices:");
                System.out.println(test_lidx + ", " + test_ridx);
                System.out.println(ltrain_lidx + ", " + ltrain_ridx + "; " + rtrain_lidx + ", " + rtrain_ridx);
                System.out.println("----------------------------------------");

                for (int j = 0; j < nEpochs; j++) {
                    System.out.println("Epoch: " + j + "; K-Fold: " + i);
                    net.fit(trainData);

                    //Evaluate on the test set:
                    Evaluation evaluation = net.evaluate(testData);
                    log.info(String.format(str, i, j, evaluation.accuracy(), evaluation.f1(), evaluation.recall(), evaluation.precision()));
                    log.info(evaluation.confusionToString());
                    results[i] = String.format(str, i, j, evaluation.accuracy(), evaluation.f1(), evaluation.recall(), evaluation.precision());

                    testData.reset();
                    trainData.reset();
                }

                //save the nn so we can analyze it later
                File locationToSave = new File(savedNetPrefix + i + ".zip");
                boolean saveUpdater = true;
                ModelSerializer.writeModel(net, locationToSave, saveUpdater);
            }

            for( String result: results ){
                System.out.println(result);
            }

        } catch(IOException | InterruptedException e) {
            System.out.println("IOEXception");
            System.out.println(e.getMessage());
        } catch(Exception e) {
            System.out.println("Exception e");
            System.out.println(e.getMessage());
        }
    }

    public static void load_and_run_network_3lbl(
            String nn_path,
            String featuresFolder,
            String labelsFolder,
            String dataName,
            String preds_path,
            int data_num
    )
    {
        try {
            PrintWriter pred_file = new PrintWriter(preds_path + data_num, "UTF-8");

            MultiLayerNetwork net = ModelSerializer.restoreMultiLayerNetwork(nn_path);

            SequenceRecordReader testFeatures = new CSVSequenceRecordReader();
            testFeatures.initialize(new NumberedFileInputSplit(featuresFolder+dataName, data_num, data_num));

            SequenceRecordReader testLabels = new CSVSequenceRecordReader();
            testLabels.initialize(new NumberedFileInputSplit(labelsFolder+dataName, data_num, data_num));

            DataSetIterator testData = new SequenceRecordReaderDataSetIterator(testFeatures, testLabels, 1, 3,
                    false, SequenceRecordReaderDataSetIterator.AlignmentMode.ALIGN_END);

            while( testData.hasNext() ) {
                //System.out.println("data!");
                DataSet ds = testData.next();
                //if( ds != null ) {
                //    System.out.println("ds not null!");
                //}

                INDArray fm = ds.getFeatureMatrix();
                //System.out.print(fm);
                //if( fm != null ){
                //    System.out.println("fm not null!");
                //}

                //TODO: create new function for getting the hidden state at each time step
                // Perhaps net.rnnTimeStep(sliceOfSequence); net.getLayer(0)
                //@syreal17 weights will be in the layer parameters
                //you'll have to iterate through each param index using something like .getParam('0_b')


                INDArray output = net.output(fm);
                //System.out.print(output);

                for( int i=0; i<output.size(2); i++){
                    System.out.println(i);
                    double class0pred = output.getDouble(0,0,i);
                    double class1pred = output.getDouble(0,1,i);
                    double class2pred = output.getDouble(0,2,i);
                    double max = Math.max(class0pred, class1pred);
                    max = Math.max(max,class2pred);
                    String classpred = "";

                    if(max == class0pred && max == class1pred && class2pred == max){
                        classpred = "012Tie";
                    } else if (max == class0pred && max == class1pred){
                        classpred = "01Tie";
                    } else if (max == class0pred && max == class2pred){
                        classpred = "02Tie";
                    } else if (max == class1pred && max == class2pred){
                        classpred = "12Tie";
                    } else if (max == class0pred){
                        classpred = "0";
                    } else if (max == class1pred){
                        classpred = "1";
                    } else if (max == class2pred){
                        classpred = "2";
                    } else {
                        classpred = "error!";
                    }

                    String class0pred_s = String.valueOf(class0pred);
                    String class1pred_s = String.valueOf(class1pred);
                    String class2pred_s = String.valueOf(class2pred);
                    String max_s = String.valueOf(max);

                    pred_file.println(class0pred_s + ", " + class1pred_s + ", " + class2pred_s + ",," + max_s + ", " + classpred);
                }

                pred_file.close();
            }

        } catch (IOException | InterruptedException e){
            System.out.print(e.getMessage());
        }

    }

    public static void load_and_run_network_2lbl(
            String nn_path,
            String featuresFolder,
            String labelsFolder,
            String dataName,
            String preds_path,
            int data_num
    )
    {
        try {
            PrintWriter pred_file = new PrintWriter(preds_path + data_num, "UTF-8");

            MultiLayerNetwork net = ModelSerializer.restoreMultiLayerNetwork(nn_path);

            SequenceRecordReader testFeatures = new CSVSequenceRecordReader();
            testFeatures.initialize(new NumberedFileInputSplit(featuresFolder+dataName, data_num, data_num));

            SequenceRecordReader testLabels = new CSVSequenceRecordReader();
            testLabels.initialize(new NumberedFileInputSplit(labelsFolder+dataName, data_num, data_num));

            DataSetIterator testData = new SequenceRecordReaderDataSetIterator(testFeatures, testLabels, 1, 2,
                    false, SequenceRecordReaderDataSetIterator.AlignmentMode.ALIGN_END);

            while (testData.hasNext()) {
                //System.out.println("data!");
                DataSet ds = testData.next();
                //if( ds != null ) {
                //    System.out.println("ds not null!");
                //}

                INDArray fm = ds.getFeatureMatrix();
                //System.out.print(fm);
                //if( fm != null ){
                //    System.out.println("fm not null!");
                //}

                //TODO: create new function for getting the hidden state at each time step
                // Perhaps net.rnnTimeStep(sliceOfSequence); net.getLayer(0)
                //@syreal17 weights will be in the layer parameters
                //you'll have to iterate through each param index using something like .getParam('0_b')


                INDArray output = net.output(fm);
                //System.out.print(output);

                for (int i = 0; i < output.size(2); i++) {
                    //System.out.println(i);
                    double class0pred = output.getDouble(0, 0, i);
                    double class1pred = output.getDouble(0, 1, i);
                    double max = Math.max(class0pred, class1pred);
                    String classpred = "";

                    if (max == class0pred && max == class1pred) {
                        classpred = "01Tie";
                    } else if (max == class0pred) {
                        classpred = "0";
                    } else if (max == class1pred) {
                        classpred = "1";
                    } else {
                        classpred = "error!";
                    }

                    String class0pred_s = String.valueOf(class0pred);
                    String class1pred_s = String.valueOf(class1pred);
                    String max_s = String.valueOf(max);

                    pred_file.println(class0pred_s + ", " + class1pred_s + ", " + ",," + max_s + ", " + classpred);
                }

                pred_file.close();
            }

        } catch (IOException | InterruptedException e) {
            System.out.print(e.getMessage());
        }

    }

    public static void load_and_step_network(
            int nLabels,
            String nn_path,
            String featuresFolder,
            String labelsFolder,
            String dataName,
            int data_num
    )
    {//{, String preds_path) {
        try {
            //PrintWriter pred_file = new PrintWriter(preds_path + data_num, "UTF-8");

            MultiLayerNetwork net = ModelSerializer.restoreMultiLayerNetwork(nn_path);

            SequenceRecordReader testFeatures = new CSVSequenceRecordReader();
            testFeatures.initialize(new NumberedFileInputSplit(featuresFolder+dataName, data_num, data_num));

            SequenceRecordReader testLabels = new CSVSequenceRecordReader();
            testLabels.initialize(new NumberedFileInputSplit(labelsFolder+dataName, data_num, data_num));

            DataSetIterator testData = new SequenceRecordReaderDataSetIterator(testFeatures, testLabels, 1, nLabels,
                    false, SequenceRecordReaderDataSetIterator.AlignmentMode.ALIGN_END);

            while (testData.hasNext()) {
                //System.out.println("data!");
                DataSet ds = testData.next();
                //if( ds != null ) {
                //    System.out.println("ds not null!");
                //}

                INDArray fm = ds.getFeatureMatrix();
                //System.out.print(fm);
                //if( fm != null ){
                //    System.out.println("fm not null!");
                //}

                //TODO: get single one-hot encoding for one timestep
                INDArray col = fm.getColumn(0);
                INDArray row = fm.getRow(0).getColumn(0);
                //INDArray in = Nd4j.create(1,256);
                row.setShape(1,256);

                System.out.print(row);

                //TODO: create new function for getting the hidden state at each time step
                // Perhaps net.rnnTimeStep(sliceOfSequence); net.getLayer(0)
                //@syreal17 weights will be in the layer parameters
                //you'll have to iterate through each param index using something like .getParam('0_b')
                net.rnnTimeStep(row);


                //INDArray output = net.output(fm);
            }

        } catch (IOException | InterruptedException e){
            System.out.print(e.getMessage());
        }
    }
}
