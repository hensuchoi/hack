install.packages('tm',repos="http://cran.rstudio.com/")
install.packages('SnowballC',repos="http://cran.rstudio.com/")
library(tm)
library(SnowballC)
library(wordcloud)
library(RColorBrewer)


#**************DATA ANALYSIS***************#

vuln1 <- read.csv("C:/Users/HenSu/Desktop/hackaton (1).csv")
vuln <- read.csv("C:/Users/HenSu/Desktop/hackaton (3).csv")
fab <- read.csv("C:/Users/HenSu/Desktop/fabricant.csv")
table(vuln$year)
hist(vuln$year, breaks = 16, col = "grey", main = " Number of vulnerabilities per year", xlim=c(1999,2015), ylim=c(0,10000))
axis(1, c(1999,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010,2011,2012,2013,2014,2015))


#*************TEXT MINING****************

lastyear=subset(vuln, vuln$year==2014)
d<-data.frame (lastyear$description)
ds <- DataframeSource(d)
myCorpus<-Corpus(ds)

#data cleaning
myCorpus <- tm_map(myCorpus, tolower)
myCorpus <- tm_map(myCorpus, removePunctuation)
myCorpus <- tm_map(myCorpus, removeNumbers)
removeURL <- function(x) gsub("http[[:alnum:]]*", "", x)
myCorpus <- tm_map(myCorpus, removeURL)
myCorpus <- tm_map(myCorpus, stemDocument)
myStopWords <- c(stopwords())
myStopwords <- c(stopwords('english'), "vulnerability","vulnerabilities","multiple","allows","via","aka","affect","related","scripting","unspecified","certif","vector")
myCorpus <- tm_map(myCorpus, removeWords, myStopwords)

corpus_clean <- tm_map(myCorpus, PlainTextDocument)
myTdm <- TermDocumentMatrix(corpus_clean)

findFreqTerms(myTdm,lowfreq=20)

m<-as.matrix(myTdm)
wordFreq <- sort(rowSums(m), decreasing=TRUE)

# word cloud
set.seed(375) # to make it reproducible
grayLevels <- gray( (wordFreq+10) / (max(wordFreq)+10) )
wordcloud(words=names(wordFreq), freq=wordFreq, min.freq=10, random.order=F,colors=grayLevels)

#******* Machine learning****************

#k means analysis

Tdm2 <- removeSparseTerms(myTdm, sparse=0.95)
m2 <- as.matrix(Tdm2)
distMatrix <- dist(scale(m2))
fit <- hclust(distMatrix, method="ward")
plot(fit)

rect.hclust(fit, k=8)
(groups <- cutree(fit, k=8))



#subsets of platforms
cisco<-subset(vuln, grepl("cisco",vuln$description))
ibm<-subset(vuln, grepl("ibm",vuln$description))
micros<-subset(vuln, grepl("microsoft",vuln$description))
linux<-subset(vuln, grepl("linux",vuln$description))
oracle<-subset(vuln, grepl("oracle",vuln$description))
android<-subset(vuln, grepl("android",vuln$description))
php<-subset(vuln, grepl("hp",vuln$description))
ios<-subset(vuln, grepl("ios",vuln$description))
solaris<-subset(vuln, grepl("solaris",vuln$description))
apache<-subset(vuln, grepl("apache",vuln$description))
wordpress<-subset(vuln, grepl("wordpress",vuln$description))
adobe<-subset(vuln, grepl("adobe",vuln$description))
firefox<-subset(vuln, grepl("firefox",vuln$description))

inject<-subset(vuln, grepl("inject",vuln$description))
cross<-subset(vuln, grepl("cross-site",vuln$description))


#******android

d<-data.frame (android$description)
ds <- DataframeSource(d)
myCorpus<-Corpus(ds)
myCorpus <- tm_map(myCorpus, tolower)
myCorpus <- tm_map(myCorpus, removePunctuation)
myCorpus <- tm_map(myCorpus, removeNumbers)
removeURL <- function(x) gsub("http[[:alnum:]]*", "", x)
myCorpus <- tm_map(myCorpus, removeURL)
myCorpus <- tm_map(myCorpus, stemDocument)
myCorpus <- tm_map(myCorpus, removeWords, myStopwords)
myCorpus <- tm_map(myCorpus, removeWords, "android")
corpus_clean <- tm_map(myCorpus, PlainTextDocument)
myTdm <- TermDocumentMatrix(corpus_clean)
m<-as.matrix(myTdm)
wordFreq <- sort(rowSums(m), decreasing=TRUE)
# word cloud
set.seed(222) 
#grayLevels <- gray( (wordFreq+10) / (max(wordFreq)+10) )
wordcloud(words=names(wordFreq), freq=wordFreq, min.freq=10, random.order=T,colors=brewer.pal(8, "Dark2"))


#******PHP

d<-data.frame (php$description)
ds <- DataframeSource(d)
myCorpus<-Corpus(ds)
myCorpus <- tm_map(myCorpus, tolower)
myCorpus <- tm_map(myCorpus, removePunctuation)
myCorpus <- tm_map(myCorpus, removeNumbers)
removeURL <- function(x) gsub("http[[:alnum:]]*", "", x)
myCorpus <- tm_map(myCorpus, removeURL)
myCorpus <- tm_map(myCorpus, stemDocument)
myCorpus <- tm_map(myCorpus, removeWords, myStopwords)
myCorpus <- tm_map(myCorpus, removeWords, "android")
corpus_clean <- tm_map(myCorpus, PlainTextDocument)
myTdm <- TermDocumentMatrix(corpus_clean)
m<-as.matrix(myTdm)
wordFreq <- sort(rowSums(m), decreasing=TRUE)
# word cloud
set.seed(222) 
#grayLevels <- gray( (wordFreq+10) / (max(wordFreq)+10) )
wordcloud(words=names(wordFreq), freq=wordFreq, min.freq=10, random.order=F,colors=brewer.pal(8, "Dark2"))

#******Oracle

d<-data.frame (oracle$description)
ds <- DataframeSource(d)
myCorpus<-Corpus(ds)
myCorpus <- tm_map(myCorpus, tolower)
myCorpus <- tm_map(myCorpus, removePunctuation)
myCorpus <- tm_map(myCorpus, removeNumbers)
removeURL <- function(x) gsub("http[[:alnum:]]*", "", x)
myCorpus <- tm_map(myCorpus, removeURL)
myCorpus <- tm_map(myCorpus, stemDocument)
myCorpus <- tm_map(myCorpus, removeWords, myStopwords)
myCorpus <- tm_map(myCorpus, removeWords, "oracle")
corpus_clean <- tm_map(myCorpus, PlainTextDocument)
myTdm <- TermDocumentMatrix(corpus_clean)
m<-as.matrix(myTdm)
wordFreq <- sort(rowSums(m), decreasing=TRUE)
# word cloud
set.seed(222) 
wordcloud(words=names(wordFreq), freq=wordFreq, min.freq=10, random.order=F,colors=brewer.pal(8, "Dark2"))

#********Adobe
d<-data.frame (adobe$description)
ds <- DataframeSource(d)
myCorpus<-Corpus(ds)
myCorpus <- tm_map(myCorpus, tolower)
myCorpus <- tm_map(myCorpus, removePunctuation)
myCorpus <- tm_map(myCorpus, removeNumbers)
removeURL <- function(x) gsub("http[[:alnum:]]*", "", x)
myCorpus <- tm_map(myCorpus, removeURL)
myCorpus <- tm_map(myCorpus, stemDocument)
myCorpus <- tm_map(myCorpus, removeWords, myStopwords)
myCorpus <- tm_map(myCorpus, removeWords, "adobe")
corpus_clean <- tm_map(myCorpus, PlainTextDocument)
myTdm <- TermDocumentMatrix(corpus_clean)
m<-as.matrix(myTdm)
wordFreq <- sort(rowSums(m), decreasing=TRUE)
# word cloud
set.seed(222) 
#grayLevels <- gray( (wordFreq+10) / (max(wordFreq)+10) )
wordcloud(words=names(wordFreq), freq=wordFreq, min.freq=10, random.order=F,colors=brewer.pal(8, "Dark2"))

#***************inject
d<-data.frame (inject$description)
ds <- DataframeSource(d)
myCorpus<-Corpus(ds)
myCorpus <- tm_map(myCorpus, tolower)
myCorpus <- tm_map(myCorpus, removePunctuation)
myCorpus <- tm_map(myCorpus, removeNumbers)
removeURL <- function(x) gsub("http[[:alnum:]]*", "", x)
myCorpus <- tm_map(myCorpus, removeURL)
myCorpus <- tm_map(myCorpus, stemDocument)
myCorpus <- tm_map(myCorpus, removeWords, myStopwords)
myCorpus <- tm_map(myCorpus, removeWords, "inject")
corpus_clean <- tm_map(myCorpus, PlainTextDocument)
myTdm <- TermDocumentMatrix(corpus_clean)
m<-as.matrix(myTdm)
wordFreq <- sort(rowSums(m), decreasing=TRUE)
# word cloud
set.seed(222) 
#grayLevels <- gray( (wordFreq+10) / (max(wordFreq)+10) )
wordcloud(words=names(wordFreq), freq=wordFreq, min.freq=10, random.order=F,colors=brewer.pal(8, "Dark2"))

d<-data.frame (cross$description)
ds <- DataframeSource(d)
myCorpus<-Corpus(ds)
myCorpus <- tm_map(myCorpus, tolower)
myCorpus <- tm_map(myCorpus, removePunctuation)
myCorpus <- tm_map(myCorpus, removeNumbers)
removeURL <- function(x) gsub("http[[:alnum:]]*", "", x)
myCorpus <- tm_map(myCorpus, removeURL)
myCorpus <- tm_map(myCorpus, stemDocument)
myCorpus <- tm_map(myCorpus, removeWords, myStopwords)
myCorpus <- tm_map(myCorpus, removeWords, "crosssite")
corpus_clean <- tm_map(myCorpus, PlainTextDocument)
myTdm <- TermDocumentMatrix(corpus_clean)
m<-as.matrix(myTdm)
wordFreq <- sort(rowSums(m), decreasing=TRUE)
# word cloud
set.seed(222) 
#grayLevels <- gray( (wordFreq+10) / (max(wordFreq)+10) )
wordcloud(words=names(wordFreq), freq=wordFreq, min.freq=10, random.order=F,colors=brewer.pal(8, "Dark2"))



