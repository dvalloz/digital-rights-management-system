"""
Funciones auxiliares para mapeo estático de claves y vectores.
"""

def getclave(nombre: str) -> bytes:
    """Devuelve la clave AES de 16 bytes correspondiente a un archivo."""
    claves = {
        'foto_dani_e.jpeg': b"\xc9\x019\xe9\xbci\xbb\x9f\x8f\xe9B\x86DW\xab=",
        'foto1_e.jpeg': b'_\\\xba\x9e\xaev\xf1#\x9d\xecg\xe4\x85\xe29/',
        'foto2_e.jpg': b'\xc8;\x07\x84SUV\xf2\x8bvk\x88y_k>',
        'foto_miguel_e.jfif': b'\x1d\xde\x89c\xbe~\x85cz6-j-\xecq\xfb',
        'video_dani_e.mp4': b'\xf6\x95;\x1b\xd7T\xbf\xc2\x03\xb9Yq\x83LN\x85',
        'video_miguel_e.mp4': b'R\x9f\x15\xf1\xb4\xf6\xd7E\x9c\x1b\x86N\x1ex\xd6t',
        'video1_e.mp4': b'JBre\xd3o\xf2/\xf9\xdeV\x7f\x86\xdcd\xf9',
        'video2_e.mp4': b'\x9d&\x88XR\x96\x17Abz\x0c\x8ct\xec\xe66',
    }
    return claves.get(nombre, b'')


def getvector(nombre: str) -> bytes:
    """Devuelve el vector de inicialización (IV) de 16 bytes correspondiente a un archivo."""
    vectores = {
        'foto_dani_e.jpeg': b'\xf5\xc7\x19\x843\xf1\r\x91\xdfV\xca-\x88*r\x83',
        'foto1_e.jpeg': b'`\x0b,\x17k\x02vs!\xa5\xab\xa9\x1dzGr',
        'foto2_e.jpg': b'\x8f9;"Fj\x9e_^K\xbbo\xc9\xfa\xb5a',
        'foto_miguel_e.jfif': b'n\x8b_+\xac+\x16\xbe\x17\xb2\xbfp\x07\x926\xdc',
        'video_dani_e.mp4': b'*x\xeb\xda\xaaD;s1\x1f\xe2w~\x18Mk',
        'video_miguel_e.mp4': b'\xcb\xd5\x88S\x97\xfb\xe9K\x8aV\xed\x8e\xdczr\xe4',
        'video1_e.mp4': b'~\xe6\x9a\x99\x0b\x9a\xfc\x00+\xa5rQ\xe6\xbcJ\xa1',
        'video2_e.mp4': b'\xe0Q\x8aQ\xca\xdc\x0f\xa8z\x97\xee\x90\xd4\x0c\xcfQ',
    }
    return vectores.get(nombre, b'')
