import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # or any {'0', '1', '2'}
import tensorflow as tf
tf.compat.v1.logging.set_verbosity(tf.compat.v1.logging.WARN)  # or any {DEBUG, INFO, WARN, ERROR, FATAL}
from tensorflow.keras.layers import *
from tensorflow.keras.models import *




class CustomDistiller(Model):
    def __init__(self, modalities=[], adapter_size=128, n_classes=[]) -> None:
        super(CustomDistiller, self).__init__()
        self.n_classes = n_classes
        self.modalities = modalities
        self.adapter_size = adapter_size
        self._validate()
        
        shared_representation = stack(
            [
                Concatenate()(
                    wrap_adapter_multi(modalities, adapter_size) 
                )
            ]
            + get_sr_layers(adapter_size)
        )
        
        outputs = []
        for n_class in n_classes:
            outputs.append(stack([shared_representation] + get_ts_layers(classes_count=n_class, adapter_size=adapter_size)))
        self.model = Model(
            name='Distiller',
            inputs=[modal.input for modal in modalities],
            outputs= outputs
        )


    def call(self, inputs, training=None):
        # See: https://www.tensorflow.org/guide/keras/custom_layers_and_models#the_model_class
        return self.model(inputs, training)


    def _validate(self):
        # modalities and n_classess array must not be empty .
        assert len(self.modalities) != 0
        assert len(self.n_classes) != 0
        
        # n_classes values must represent the number of classes in each task.
        # and therefore must be positive integers.
        for nclass in self.n_classes:
            assert nclass >= 1
        
        # adapter_size must be positive.
        assert self.adapter_size >= 1


    def get_model_for_pretraining(self, model):
        model_w_adapter = wrap_adapter(model, self.adapter_size)
        outputs = []
        for n_class in self.n_classes:
            outputs.append(stack([model_w_adapter, Dense(n_class, activation='softmax')]))
        return Model(
            name='pretraining_model',
            inputs=model.input,
            outputs=outputs
        )


    def freeze_for_finetuning(self):
        for modal in self.modalities:
            for layer in modal.layers:
                layer.trainable = False

  
    def unfreeze_for_finetuning(self):
        for modal in self.modalities:
            for layer in modal.layers:
                layer.trainable = True
        
        
    def fit(self, x, y, **kwargs):
        loss_fn = tf.keras.losses.CategoricalCrossentropy(from_logits=False)
        for features, modal in zip(x, self.modalities):
            print('##################### {} ##########################'.format(modal.name.upper()))
            pretraining_model = self.get_model_for_pretraining(modal)
            pretraining_model.compile(
                optimizer=tf.keras.optimizers.Adam(learning_rate=0.002),
                loss=loss_fn,
                metrics=[['accuracy']] * len(self.n_classes)
            ) 
            
            pretraining_model.fit(features, y, **kwargs)

        # FINE-TUNE
        print('##################### FINE-TUNING ##########################')
        self.freeze_for_finetuning()
        
        self.model.compile(
            optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
            loss=loss_fn,
            metrics=['accuracy']
        )

        self.model.fit(x,y, **kwargs)

        self.unfreeze_for_finetuning()



###################
# Model utilities #
###################


def stack(layers):
    '''
    Using the Functional-API of Tensorflow to build a sequential
    network (stacked layers) from list of layers.
    '''
    layer_stack = None
    for layer in layers:
        if layer_stack is None:
            layer_stack = layer
        else:
            layer_stack = layer(layer_stack)
    return layer_stack


def get_adapter_layers(adapter_size):
    return [
        Dropout(0.2),
        Dense(adapter_size),
        ReLU()
    ]


def wrap_adapter(model, adapter_size):
    return stack([model.output, *get_adapter_layers(adapter_size)])


def wrap_adapter_multi(models, adapter_size):
    return [wrap_adapter(model, adapter_size) for model in models]


def get_sr_layers(adapter_size):
    # SR = Shared Representation
    return [
        Dropout(0.2),
        Dense(adapter_size),
        ReLU(),
        Dropout(0.2),
    ]


def get_ts_layers(classes_count, adapter_size):
    # TS = Task Specific
    return [
        Dense(adapter_size),
        ReLU(),
        Dropout(0.2),
        Dense(classes_count),
        Softmax()
    ]