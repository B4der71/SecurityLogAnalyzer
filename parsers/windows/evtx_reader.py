from Evtx.Evtx import Evtx


class EVTXReader:
    """
    Reads Windows .evtx files and yields each event as XML.
    """

    def read(self, file_path: str):
        """
        Yield each event in the EVTX file as an XML string.
        """

        with Evtx(file_path) as log:
            for record in log.records():
                yield record.xml()