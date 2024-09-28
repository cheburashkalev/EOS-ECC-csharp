// See https://aka.ms/new-console-template for more information
using eos_ecc;
using System.Diagnostics;
var data = "asd_k1y1c_asd";
var pvt_key = "5HykXsnGGPVXV8ozJcZ5ivjXK3uu6Yr7VMvoHMXxN1RYAjS4HBN";
var pub_key = "EOS5NEn9cg7MTiYp59KFsYaYj3wqWBHusT6WTCFEFm5QAw5BAv79A";
//создаем объект
Stopwatch stopwatch = new Stopwatch();
//засекаем время начала операции
stopwatch.Start();
var sign = ApiCommon.SignData(data, pvt_key);
stopwatch.Stop();
//смотрим сколько миллисекунд было затрачено на выполнение
Console.WriteLine(stopwatch.ElapsedMilliseconds);
stopwatch = new Stopwatch();
//засекаем время начала операции
stopwatch.Start();
var res = ApiCommon.VerifySignature(sign, data, pub_key);
stopwatch.Stop();
//смотрим сколько миллисекунд было затрачено на выполнение
Console.WriteLine(stopwatch.ElapsedMilliseconds);
Console.WriteLine("Hello, World!");
