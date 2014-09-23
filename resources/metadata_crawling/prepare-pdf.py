__author__ = 'Xaime'
# - *- coding: utf- 8 - *- .
from pyPdf import PdfFileReader, PdfFileWriter
from pyPdf.generic import NameObject, createStringObject
import argparse
import sys

parser = argparse.ArgumentParser(description=u'Limpia los metadatos de un PDF y opcionalmente añade título y autor')
parser.add_argument("input", help="fichero pdf origen")
parser.add_argument("output", help="fichero pdf destino")
args = parser.parse_args()

fin = file(args.input, 'rb')
pdfIn = PdfFileReader(fin)
pdfOut = PdfFileWriter()

for page in range(pdfIn.getNumPages()):
    pdfOut.addPage(pdfIn.getPage(page))

info = pdfOut._info.getObject()
del info[NameObject('/Producer')]


title = raw_input("Titulo:").decode(sys.stdin.encoding)
author = raw_input("Autor:").decode(sys.stdin.encoding)
info.update({
    NameObject('/Title'): createStringObject(title),
    NameObject('/Author'): createStringObject(author)
})



fout = open(args.output, 'wb')
pdfOut.write(fout)
fin.close()
fout.close()