"use client";
import { useEffect, useState } from "react";
import Field from "./ui/Field";
const { Keychain } = require("../password-manager-online.js");
const test = [
  '{"kvs":{"tVFlxWFM1eTTGEpYsVCBlRuJ3higOf7mhuu9BzOxHgA=":{"iv":"fdH26skhEWLslxRt","ct":"R1HHHQKR+lugNVvM36UVOomUP+m2gQNQ3n5KWjE3bVnxZ82QjcGrTWhhAN73U7LTXZxQ96/UJ5XFIaDCRtMvC30TCVxRHscLvDbM8Yk4sQZ5"},"cveydU05Tg/CqPqB4jB9eRuqRW2zedubLv2Wo0+T9aw=":{"iv":"ZwZNo/vh7tCLloU8","ct":"QhRBxA/Y6uxJJsKPCnPl9mu/WxaxNC0QuzDAHrcftk7TasqnvBBWYXjRbrq8nPxSxJ+jq/F6CMwoJ2mBHJ9N83pGJ6wSugZj/6Xeifny5A1J"},"CirRlMqSTV6z11WPKyGBVqgN4JuuTp1OqgMadkwJbM8=":{"iv":"Y3pGjgiDGcAImWrz","ct":"lUnEEP/QECE6RvtfKpBsfcFTZRnBrN0ScBER2PkUC3mXX10GQ2GhxnuiGcymU3M2YyyW1zOy2Ia/ldSfgqA3mnkaX/asTdbXu4uEtoDiIMd+"}},"salt":"lTa5dQBqzQrsJVkXvKA1RA==","verifyTag":"bD1cUUcGwJ699e8g7hrcOqpSFyEYMcp4PZDA8fez50A="}',
  "lIYG+tjo0uXHo5Gp4mtQCxME8imkTDELLuOPOo4ku9M=",
];

export default function Page() {
  var baseKvs = {};
  const [search, setSearch] = useState("");
  const [ready, setReady] = useState(false);
  const [updated, setUpdated] = useState(false);
  const [kvs, setKvs] = useState();
  const [result, setResult] = useState([]);
  const [addDomain, setAddDomain] = useState([]);
  const [addPassword, setAddPassword] = useState([]);
  const [searchFailed, setSearchFailed] = useState(false);
  const [masterPass, setMasterPass] = useState("");
  const [masterValid, setMasterValid] = useState(true);

  function handleChange(event) {
    setSearch(event.target.value);
  }
  function handleMasterPass(event) {
    setMasterPass(event.target.value);
  }
  function handleAddDomain(event) {
    setAddDomain(event.target.value);
  }
  function handleAddPassword(event) {
    setAddPassword(event.target.value);
  }

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  function deleteEntry(domain) {
    baseKvs = kvs;
    baseKvs.remove(domain);
    setKvs(baseKvs);
  }

  function addSubmit(event) {
    event.preventDefault();
    baseKvs = kvs;
    console.log(Object.keys(baseKvs.data.kvs).length);
    baseKvs.set(addDomain, addPassword).then(() => {
      setKvs(baseKvs);
      console.log(Object.keys(baseKvs.data.kvs).length);
      setUpdated(true);
      setAddPassword("");
      setAddDomain("");
      sleep(2000).then(() => {
        setUpdated(false);
      });
    });
  }

  function searchSubmit(event) {
    event.preventDefault();
    kvs.get(search).then((data) => {
      if (data == null) {
        setSearchFailed(true);
        setResult([]);
      } else {
        setResult([search, data]);
        setSearchFailed(false);
      }
    });
    console.log(result);
  }
  function auth(event) {
    event.preventDefault();
    try {
      baseKvs = Keychain.load(masterPass, test[0], test[1]).then((data) => {
        setKvs(data);
        setReady(true);
      });
    } catch {
      setReady(false);
      setMasterValid(false);
    }
  }
  useEffect(() => {
    const decryptAsync = async () => {};
    decryptAsync();
  }, []);
  return ready ? (
    <main className="flex flex-row justify-center w-screen pt-16 space-y-8">
      <div className="w-1/2 space-y-4">
        <h1 className="text-3xl font-semibold text-[#4F39F6]">Secure Vault</h1>
        <form action="" className="space-y-4" onSubmit={addSubmit}>
          <h1 className="text-2xl font-medium">Add or update domain</h1>
          <div className="flex flex-row space-x-3">
            <div className="flex flex-col space-y-2 w-full">
              <label htmlFor="domain">Domain:</label>
              <input
                type="text"
                value={addDomain}
                onChange={handleAddDomain}
                placeholder="Enter new or existing domain"
                required
                className="rounded-md px-2 py-2 bg-gray-100 border border-gray-200 w-full"
              />
            </div>
            <div className="flex flex-col space-y-2 w-full">
              <label htmlFor="password">Password:</label>
              <input
                type="password"
                value={addPassword}
                onChange={handleAddPassword}
                placeholder="Enter password"
                required
                className="rounded-md px-2 py-2 bg-gray-100 border border-gray-200 w-full"
              />
            </div>
          </div>
          <button className="text-white bg-[#4F39F6] px-3 py-3 w-full rounded-md">
            Add or update domain details
          </button>
          {updated ? (
            <p className="text-green-400">
              The domain and password was added successfully
            </p>
          ) : (
            <div></div>
          )}
        </form>
        <form action="" onSubmit={searchSubmit}>
          <h1 className="text-2xl font-medium">Retrieve password</h1>
          <div className="flex flex-col space-y-2">
            <label htmlFor="domain">Enter the domain:</label>
            <div className="flex flex-row space-x-3 items-center">
              <input
                type="text"
                placeholder="www.example.com"
                required
                value={search}
                onChange={handleChange}
                className="rounded-md px-2 py-2 bg-gray-100 border border-gray-200 w-full"
              />
              <button className="w-fit text-nowrap px-2 py-3 text-white bg-[#4F39F6] rounded-md">
                Get password
              </button>
            </div>
          </div>
        </form>
        {searchFailed ? (
          <p className="text-red-500">
            No such domain exists in the key value store
          </p>
        ) : (
          <div></div>
        )}
        <div>
          <div className="font-semibold flex flex-row text-xl">
            <p className="w-1/3">Domain</p>
            <p className="w-2/3">Password</p>
          </div>
          {result.length > 1 ? (
            <Field
              domain={result[0]}
              password={result[1]}
              deleteEntry={deleteEntry}
            />
          ) : (
            <br />
          )}
        </div>
      </div>
    </main>
  ) : (
    <main className="flex flex-row items-center justify-center w-screen h-screen ">
      <div className="shadow-[#4F39F6] border border-[#4F39F6] rounded-xl shadow-lg py-16 px-12 w-3/12">
        <h1 className="font-bold text-[#4F39F6] text-2xl text-center pb-16 pt-1">
          Secure Vault
        </h1>
        <form className="flex flex-col space-y-8" onSubmit={auth}>
          <div className="flex flex-col space-y-2">
            <label>Master password :</label>
            <input
              type="password"
              className="border outline-[#4F39F6] focus:border-[#4F39F6] px-2 py-3 rounded-md"
              placeholder="Enter master password"
              value={masterPass}
              onChange={handleMasterPass}
            />
          </div>
          <p className="text-red-500">Wrong password. Retry.</p>
          <button
            className="bg-[#4F39F6] text-white w-full rounded-md py-3"
            type="submit"
          >
            Unlock Vault
          </button>
        </form>
      </div>
    </main>
  );
}
