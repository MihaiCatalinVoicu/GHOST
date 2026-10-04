# V-M14 diagnostics only (used with -PwhyKeeping): R8 prints the path that keeps each class.
-whyareyoukeeping class androidx.media3.datasource.DefaultHttpDataSource
-whyareyoukeeping class androidx.media3.datasource.UdpDataSource
-whyareyoukeeping class androidx.media3.datasource.FileDataSource
-whyareyoukeeping class androidx.media3.transformer.InAppMp4Muxer
-whyareyoukeeping class androidx.media3.exoplayer.analytics.MediaMetricsListener
-whyareyoukeeping class androidx.media3.exoplayer.image.BitmapFactoryImageDecoder
# Review I2 (2026-10-04): with Mp4Extractor-only and FragmentedMp4Extractor-only factories and the
# G-M3 renderers factory, why the other extractors, the image asset loader and ExifInterface stay.
-whyareyoukeeping class androidx.media3.extractor.DefaultExtractorsFactory
-whyareyoukeeping class androidx.media3.exoplayer.source.DefaultMediaSourceFactory
-whyareyoukeeping class androidx.media3.extractor.mkv.MatroskaExtractor
-whyareyoukeeping class androidx.media3.extractor.heif.HeifExtractor
-whyareyoukeeping class androidx.media3.transformer.ImageAssetLoader
-whyareyoukeeping class androidx.media3.datasource.DataSourceBitmapLoader
-whyareyoukeeping class androidx.exifinterface.media.ExifInterface
