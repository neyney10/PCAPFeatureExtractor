from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, BatchNormalization, Conv1D, ReLU, MaxPooling1D, Flatten, Bidirectional, GRU
from tensorflow.keras.constraints import max_norm 
from . import CustomDistiller



class Distiller(Model):
    def __init__(self, n_classes=[]) -> None:
        super(Distiller, self).__init__()
        self.model = CustomDistiller(
            modalities=[
                wang_payload_modality(784),
                lopez_protocol_header_fields_modality(32)
            ],
            adapter_size=128, 
            n_classes=n_classes
        )


    def call(self, inputs, training=None):
        # See: https://www.tensorflow.org/guide/keras/custom_layers_and_models#the_model_class
        return self.model(inputs, training)



def wang_payload_modality(payload_size=784):
    input_layer_payload_modality = Input(shape=(payload_size,1), name='input_payload')
    return Model(
        name='Wang payload modality (nbytes)',
        inputs=input_layer_payload_modality,
        outputs=stack([
            input_layer_payload_modality,
            BatchNormalization(),
            Conv1D(16, 25, name='Conv1D_payload_1'),
            ReLU(),
            MaxPooling1D(3, name='MaxPooling1D_payload_1'),
            Conv1D(32, 35, name='Conv1D_payload_2'),
            ReLU(),
            MaxPooling1D(3, name='MaxPooling1D_payload_2'),
            Flatten(), 
        ])
    )


def lopez_protocol_header_fields_modality(packet_count=32):
    input_layer_protocol_fields_modality = Input(shape=(packet_count,4), name='input_protocol_fields')
    return Model(
        name='Lopez protocol header fields modality',
        inputs=input_layer_protocol_fields_modality,
        outputs=stack([
            input_layer_protocol_fields_modality,
            BatchNormalization(),
            Bidirectional(GRU(64, return_sequences=True, kernel_constraint=max_norm(3))),
            ReLU(),
            Flatten(),
        ])
    )



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