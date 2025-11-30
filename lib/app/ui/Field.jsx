"use client";

import { useState } from "react";
import Image from "next/image";

export default function Field({ domain, password, deleteEntry }) {
  const [visible, setVisible] = useState(false);
  return (
    <div className="flex flex-row py-3 items-center">
      <label className="w-1/3 pr-10 truncate">{domain}</label>
      <div className="w-2/3 flex flex-row items-center space-x-3">
        <input
          type={visible ? "text" : "password"}
          value={password}
          readOnly
          className="rounded-md px-2 py-2 bg-gray-100 border border-gray-200 w-full"
        />
        <button
          onClick={() => {
            setVisible(!visible);
          }}
        >
          {visible ? (
            <Image src="/eye.svg" alt="visible" width={22} height={22} />
          ) : (
            <Image src="/eye-closed.svg" alt="visible" width={25} height={25} />
          )}
        </button>
        <button
          onClick={() => {
            deleteEntry(domain);
          }}
        >
          <Image src="/delete.svg" alt="visible" width={25} height={25} />
        </button>
      </div>
    </div>
  );
}
