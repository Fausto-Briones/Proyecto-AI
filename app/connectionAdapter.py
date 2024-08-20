import joblib
import pandas as pd
import struct
import socket
class ConnectionAdapter:

    def preprocess_validation_data(self,df, scaler_path='scaler.pkl', hasher_path='hasher.pkl'):
        # Categorías a mantener
        conn_state_keep = ['S0', 'SF', 'RSTOS0', 'REJ', 'OTH', 'RSTR', 'RSTO']
        proto_keep = ['icmp', 'tcp', 'udp']
        service_keep = ['dhcp', 'dns', 'http', 'ssh']

        # Convertir la columna 'history' a cadena
        df['history'] = df['history'].astype('string')

        # Convertir la columna 'history' en una lista de listas de cadenas
        history_list = df['history'].apply(lambda x: [x]).tolist()

        # Cargar el FeatureHasher
        hasher = joblib.load(hasher_path)

        # Aplicar Feature Hashing
        history_hashed = hasher.transform([{'history': hist[0]} for hist in history_list])

        # Convertir el resultado a un DataFrame
        history_hashed_df = pd.DataFrame(history_hashed.toarray(), columns=[f'history_hash_{i}' for i in range(20)])

        # Concatenar el DataFrame resultante con el original
        df = pd.concat([df.drop('history', axis=1), history_hashed_df], axis=1)

        # Eliminar features no importantes
        df = df.drop(columns=['uid', 'tunnel_parents', 'local_orig', 'local_resp', 'detailed-label'], errors='ignore')

        # Convertir algunas columnas a numéricas
        numeric_columns = [
            'ts', 'orig_pkts', 'resp_pkts', 'orig_ip_bytes', 'resp_ip_bytes',
            'duration', 'orig_bytes', 'resp_bytes'
        ]
        df[numeric_columns] = df[numeric_columns].apply(pd.to_numeric, errors='coerce')

        # Preprocesamiento de 'conn_state'
        df['conn_state'] = df['conn_state'].apply(lambda x: x if x in conn_state_keep else 'OTHERS')

        # Preprocesamiento de 'proto'
        df['proto'] = df['proto'].apply(lambda x: x if x in proto_keep else 'OTHERS')

        # Preprocesamiento de 'service'
        df['service'] = df['service'].apply(lambda x: x if x in service_keep else 'OTHERS')

        # Aplicar One-Hot Encoding
        df = pd.get_dummies(df, columns=['proto', 'conn_state', 'service'])

        # Asegurar que las columnas dummy están presentes
        expected_dummies_columns = [
            'proto_icmp', 'proto_tcp', 'proto_udp', 'proto_OTHERS',
            'conn_state_OTH', 'conn_state_OTHERS', 'conn_state_REJ', 'conn_state_RSTO',
            'conn_state_RSTOS0', 'conn_state_RSTR', 'conn_state_S0', 'conn_state_SF',
            'service_dhcp', 'service_dns', 'service_http', 'service_ssh', 'service_OTHERS'
        ]
        for col in expected_dummies_columns:
            if col not in df.columns:
                df[col] = 0

        # Convertir IPs a Números Enteros
        df['id.orig_h'] = df['id.orig_h'].apply(self.ip_to_int)
        df['id.resp_h'] = df['id.resp_h'].apply(self.ip_to_int)

        # Cargar el scaler y normalizar
        scaler = joblib.load(scaler_path)
        columns_to_normalize = [
            'ts', 'id.orig_h', 'id.orig_p', 'id.resp_h', 'id.resp_p', 'duration',
            'orig_bytes', 'resp_bytes', 'missed_bytes', 'orig_pkts',
            'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes'
        ] + [f'history_hash_{i}' for i in range(20)] + expected_dummies_columns


        # Reordenar las columnas
        expected_columns = ['ts','id.orig_h', 'id.orig_p','id.resp_h','id.resp_p', 'duration', 'orig_bytes', 'resp_bytes', 'missed_bytes',
        'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes', 'history_hash_0','history_hash_1',
        'history_hash_2','history_hash_3', 'history_hash_4','history_hash_5', 'history_hash_6', 'history_hash_7',
        'history_hash_8','history_hash_9', 'history_hash_10', 'history_hash_11','history_hash_12','history_hash_13','history_hash_14',
        'history_hash_15','history_hash_16','history_hash_17','history_hash_18','history_hash_19',
        'proto_icmp','proto_tcp', 'proto_udp','conn_state_OTH','conn_state_OTHERS','conn_state_REJ',
        'conn_state_RSTO','conn_state_RSTOS0', 'conn_state_RSTR','conn_state_S0','conn_state_SF',
        'service_OTHERS','service_dhcp','service_dns','service_http','service_ssh', 'proto_OTHERS'
        ]


        df_scaled = df[expected_columns]
        df_scaled.info()
        df_scaled[df_scaled.columns] = scaler.transform(df_scaled[df_scaled.columns])

        if 'label' in df.columns:
            labels = df['label'].apply(lambda x: 1 if x == 'Malicious' else 0).astype('int64')
            features = df.drop('label', axis=1)
            return df_scaled, labels
        else:
            return df_scaled
    
    def ip_to_int(self,ip):
        return struct.unpack("!I", socket.inet_aton(ip))[0]
